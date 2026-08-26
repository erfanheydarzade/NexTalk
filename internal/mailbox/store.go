// Package mailbox provides a persistent message store for a local identity.
//
// Every identity keeps its conversations in <id>.mailbox.np next to its
// <id>.json key file — a nanopack-binary record file (internal/binstore,
// CRC-framed) so history is compact and corruption is detected. Threads are
// keyed either by peer ID (direct messages) or by "ctx:<context_id>"
// (group/multi-message threads), so both the interactive shell and one-shot
// CLI commands (listen, mailbox) observe the same history across process
// restarts. The pre-nanopack <id>.mailbox.json format is still READ and
// migrated on first load.
//
// SECURITY NOTE: writes are atomic tmp+rename best-effort, not crash-safe
// (no WAL/fsync).
package mailbox

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk/internal/binstore"
	"github.com/erfanheydarzade/nanopack"
)

const (
	schemaID byte = 41

	groupPrefix = "ctx:"
)

// Direction distinguishes incoming from outgoing messages.
type Direction string

const (
	Incoming Direction = "in"
	Outgoing Direction = "out"
)

// Kind distinguishes direct messages from group (multi-message) traffic.
type Kind string

const (
	Direct Kind = "dm"
	Group  Kind = "group"
)

// Message is a single chat entry.
type Message struct {
	ID        string    `json:"id"`
	Direction Direction `json:"direction"`
	Kind      Kind      `json:"kind"`
	Body      string    `json:"body"`
	Timestamp int64     `json:"timestamp"` // unix millis
	IsRead    bool      `json:"is_read"`

	// Group-only fields. Sender is the message author inside a group thread;
	// ContextName is a display-name snapshot taken at receive time.
	Sender      string `json:"sender,omitempty"`
	ContextID   string `json:"context_id,omitempty"`
	ContextName string `json:"context_name,omitempty"`
}

// Thread is one conversation. Key is a peer ID for DMs or "ctx:<id>" for groups.
type Thread struct {
	Key      string    `json:"key"`
	Title    string    `json:"title,omitempty"`
	Messages []Message `json:"messages"`
}

func (t *Thread) unread() int {
	n := 0
	for _, m := range t.Messages {
		if !m.IsRead {
			n++
		}
	}
	return n
}

func (t *Thread) lastActivity() int64 {
	if len(t.Messages) == 0 {
		return 0
	}
	return t.Messages[len(t.Messages)-1].Timestamp
}

// Store is the persistent mailbox for one identity.
type Store struct {
	mu      sync.Mutex
	file    string
	threads map[string]*Thread // key -> thread
}

// messageBin is the nanopack record shape of one Message. ThreadKey is
// stored per-record so the file is a flat record list; threads are
// reconstructed on load in encounter order (which Save keeps stable:
// thread-by-thread, most recent activity first).
//
//nanopack:schema id=41
type messageBin struct {
	ThreadKey   string `bin:"1"`
	ID          string `bin:"2"`
	Direction   uint8  `bin:"3"` // 0=in 1=out
	Kind        uint8  `bin:"4"` // 0=dm 1=group
	IsRead      uint8  `bin:"5"`
	Body        string `bin:"6"`
	Sender      string `bin:"7"`
	ContextID   string `bin:"8"`
	ContextName string `bin:"9"`
	Timestamp   uint64 `bin:"10"`
}

func (m *messageBin) MarshalBinID(e *nanopack.Encoder) error {
	put := func(id uint8, s string) { e.AddID(id, []byte(s)) }
	put(1, m.ThreadKey)
	put(2, m.ID)
	e.AddID(3, []byte{m.Direction})
	e.AddID(4, []byte{m.Kind})
	e.AddID(5, []byte{m.IsRead})
	put(6, m.Body)
	put(7, m.Sender)
	put(8, m.ContextID)
	put(9, m.ContextName)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], m.Timestamp)
	e.AddID(10, ts[:])
	return nil
}

func (m *messageBin) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case 1:
			m.ThreadKey = string(f.Data)
		case 2:
			m.ID = string(f.Data)
		case 3:
			if len(f.Data) == 1 {
				m.Direction = f.Data[0]
			}
		case 4:
			if len(f.Data) == 1 {
				m.Kind = f.Data[0]
			}
		case 5:
			if len(f.Data) == 1 {
				m.IsRead = f.Data[0]
			}
		case 6:
			m.Body = string(f.Data)
		case 7:
			m.Sender = string(f.Data)
		case 8:
			m.ContextID = string(f.Data)
		case 9:
			m.ContextName = string(f.Data)
		case 10:
			if len(f.Data) == 8 {
				m.Timestamp = binary.BigEndian.Uint64(f.Data)
			}
		}
	}
	return nil
}

func (msg *Message) toBin(threadKey string) *messageBin {
	dir := uint8(0)
	if msg.Direction == Outgoing {
		dir = 1
	}
	k := uint8(0)
	if msg.Kind == Group {
		k = 1
	}
	read := uint8(0)
	if msg.IsRead {
		read = 1
	}
	return &messageBin{
		ThreadKey:   threadKey,
		ID:          msg.ID,
		Direction:   dir,
		Kind:        k,
		IsRead:      read,
		Body:        msg.Body,
		Sender:      msg.Sender,
		ContextID:   msg.ContextID,
		ContextName: msg.ContextName,
		Timestamp:   uint64(msg.Timestamp),
	}
}

func fromBin(mb *messageBin) Message {
	dir := Incoming
	if mb.Direction == 1 {
		dir = Outgoing
	}
	k := Direct
	if mb.Kind == 1 {
		k = Group
	}
	return Message{
		ID:          mb.ID,
		Direction:   dir,
		Kind:        k,
		Body:        mb.Body,
		Timestamp:   int64(mb.Timestamp),
		IsRead:      mb.IsRead == 1,
		Sender:      mb.Sender,
		ContextID:   mb.ContextID,
		ContextName: mb.ContextName,
	}
}

// fileFor returns the backing filename for an identity's mailbox.
func fileFor(identityID string) string {
	return fmt.Sprintf("%s.mailbox.np", identityID)
}

// legacyFileFor returns the pre-nanopack JSON mailbox path, if any.
func legacyFileFor(identityID string) string {
	return fmt.Sprintf("%s.mailbox.json", identityID)
}

// Load opens (or creates) the mailbox for the given identity. The identity
// ID is used verbatim in the filename; callers must only pass IDs obtained
// from Client.Id / ResolvePeer (base58 — no separators or path characters).
func Load(identityID string) (*Store, error) {
	s := &Store{
		file:    fileFor(identityID),
		threads: make(map[string]*Thread),
	}
	records, err := binstore.Load(s.file, schemaID)
	switch {
	case err == nil:
		for _, rec := range records {
			var mb messageBin
			if nanopack.UnmarshalFastID(rec, &mb) != nil || mb.ThreadKey == "" {
				continue // skip corrupted entry rather than fail the load
			}
			s.insert(mb.ThreadKey, fromBin(&mb))
		}
		return s, nil
	case errors.Is(err, os.ErrNotExist):
		// Fall through to legacy JSON migration.
	default:
		return nil, fmt.Errorf("read %s: %w", s.file, err)
	}

	// Legacy JSON migration: read old format, persist in the new one so the
	// migration happens exactly once. A failed migration write still yields
	// the loaded state.
	data, err := os.ReadFile(legacyFileFor(identityID))
	if os.IsNotExist(err) {
		return s, nil // genuinely fresh mailbox
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", legacyFileFor(identityID), err)
	}
	var threads []*Thread
	if json.Unmarshal(data, &threads) != nil {
		return nil, fmt.Errorf("parse %s: corrupt mailbox file", legacyFileFor(identityID))
	}
	for _, t := range threads {
		if t == nil || t.Key == "" {
			continue
		}
		s.threads[t.Key] = t
	}
	_ = s.saveLocked()
	return s, nil
}

// insert appends a decoded record into its thread, creating the thread if
// needed and adopting any display-name snapshot the record carries.
func (s *Store) insert(key string, msg Message) {
	t, ok := s.threads[key]
	if !ok {
		t = &Thread{Key: key}
		s.threads[key] = t
	}
	if t.Title == "" && msg.ContextName != "" && isGroupThread(key) {
		t.Title = msg.ContextName
	}
	t.Messages = append(t.Messages, msg)
}

// saveLocked persists every message as one flat record stream, thread by
// thread in the same most-recent-activity order List uses, so a reload
// reconstructs identical state. Caller holds mu.
func (s *Store) saveLocked() error {
	ordered := make([]*Thread, 0, len(s.threads))
	for _, t := range s.threads {
		ordered = append(ordered, t)
	}
	sort.Slice(ordered, func(i, j int) bool {
		ti, tj := ordered[i].lastActivity(), ordered[j].lastActivity()
		if ti != tj {
			return ti > tj
		}
		return ordered[i].Key < ordered[j].Key // deterministic order for same-ms writes
	})

	records := make([][]byte, 0, 64)
	for _, t := range ordered {
		for i := range t.Messages {
			rec, err := nanopack.MarshalFastID(t.Messages[i].toBin(t.Key))
			if err != nil {
				return err
			}
			records = append(records, rec)
		}
	}
	if err := binstore.Save(s.file, schemaID, records); err != nil {
		return err
	}
	return nil
}

func appendDefaults(msg *Message) {
	if msg.ID == "" {
		msg.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().UnixMilli()
	}
	// Outgoing messages are by definition already seen by the user.
	if msg.Direction == Outgoing {
		msg.IsRead = true
	}
}

// AppendIncoming records a received direct message from peer.
func (s *Store) AppendIncoming(peer, body string) error {
	return s.append(peer, "", Direct, Message{Direction: Incoming, Kind: Direct, Body: body})
}

// AppendOutgoing records a sent direct message to peer.
func (s *Store) AppendOutgoing(peer, body string) error {
	return s.append(peer, "", Direct, Message{Direction: Outgoing, Kind: Direct, Body: body})
}

// AppendGroupIncoming records a received group message authored by sender.
// contextID must be the raw context ID (no "ctx:" prefix).
func (s *Store) AppendGroupIncoming(contextID, contextName, sender, body string) error {
	return s.append(groupKey(contextID), contextName, Group, Message{
		Direction:   Incoming,
		Kind:        Group,
		Body:        body,
		Sender:      sender,
		ContextID:   contextID,
		ContextName: contextName,
	})
}

// AppendGroupOutgoing records a sent group message by the local identity.
func (s *Store) AppendGroupOutgoing(contextID, contextName, body string) error {
	return s.append(groupKey(contextID), contextName, Group, Message{
		Direction:   Outgoing,
		Kind:        Group,
		Body:        body,
		Sender:      "Me",
		ContextID:   contextID,
		ContextName: contextName,
	})
}

// append adds msg to the thread identified by key (creating it if needed) and
// persists. Fields carried explicitly (title/sender/context ids) win over the
// defaults embedded in msg so late-learned display names propagate.
func (s *Store) append(key, title string, kind Kind, msg Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.threads[key]
	if !ok {
		t = &Thread{Key: key}
		s.threads[key] = t
	}
	if title != "" {
		t.Title = title
	}
	appendDefaults(&msg)
	t.Messages = append(t.Messages, msg)
	return s.saveLocked()
}

// IsGroupKey reports whether key addresses a group thread ("ctx:<id>").
func IsGroupKey(key string) bool {
	return strings.HasPrefix(key, groupPrefix)
}

// isGroupThread is the internal twin of IsGroupKey.
func isGroupThread(key string) bool { return IsGroupKey(key) }

// GroupKey builds the thread key for a context ID.
func GroupKey(contextID string) string {
	return groupKey(contextID)
}

func groupKey(contextID string) string {
	return "ctx:" + contextID
}

// Get returns a copy of the thread for key, if present.
func (s *Store) Get(key string) (*Thread, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.threads[key]
	if !ok {
		return nil, false
	}
	cp := *t
	cp.Messages = make([]Message, len(t.Messages))
	copy(cp.Messages, t.Messages)
	return &cp, true
}

// ResolveThread maps a user-typed argument to a group thread key using only
// mailbox-local knowledge. Accepted forms:
//
//   - a full thread key ("ctx:<context_id>")
//   - "ctx:<id>" / "group:<id>" references (full or unambiguous prefix)
//   - an exact context ID or unambiguous prefix of one
//   - an exact display name (case-insensitive)
//
// Peer threads are resolved by the caller (contacts/prefix rules live there).
func (s *Store) ResolveThread(arg string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref := arg
	for _, prefix := range []string{"group:", "ctx:"} {
		if rest, ok := strings.CutPrefix(ref, prefix); ok {
			ref = rest
			break
		}
	}

	// Exact context ID.
	if t, ok := s.threads[groupKey(ref)]; ok && IsGroupKey(t.Key) {
		return t.Key, nil
	}

	// Exact display name (case-insensitive), then unique ID prefix.
	lowerRef := lowerASCII(ref)
	titleMatches := make([]string, 0, 1)
	idPrefixMatches := make([]string, 0, 1)
	for _, t := range s.threads {
		if !IsGroupKey(t.Key) {
			continue
		}
		ctxID := t.Key[len("ctx:"):]
		if ref != "" && strings.HasPrefix(ctxID, ref) {
			idPrefixMatches = append(idPrefixMatches, t.Key)
		}
		if title := s.threadTitleLocked(t); title != "" && lowerASCII(title) == lowerRef {
			titleMatches = append(titleMatches, t.Key)
		}
	}
	switch {
	case len(titleMatches) == 1:
		return titleMatches[0], nil
	case len(titleMatches) > 1:
		return "", fmt.Errorf("ambiguous name %q matches %d groups — use the context ID", arg, len(titleMatches))
	case len(idPrefixMatches) == 1:
		return idPrefixMatches[0], nil
	case len(idPrefixMatches) > 1:
		return "", fmt.Errorf("ambiguous context prefix %q matches %d groups", arg, len(idPrefixMatches))
	default:
		return "", fmt.Errorf("no conversation for %q", arg)
	}
}

// threadTitleLocked returns the best known display name for t. Caller holds mu.
func (s *Store) threadTitleLocked(t *Thread) string {
	if t.Title != "" {
		return t.Title
	}
	for _, m := range t.Messages {
		if m.ContextName != "" {
			return m.ContextName
		}
	}
	return ""
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// List returns all threads sorted by most recent activity (newest first).
func (s *Store) List() []*Thread {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Thread, 0, len(s.threads))
	for _, t := range s.threads {
		cp := *t
		cp.Messages = make([]Message, len(t.Messages))
		copy(cp.Messages, t.Messages)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].lastActivity(), out[j].lastActivity()
		if ti != tj {
			return ti > tj
		}
		return out[i].Key < out[j].Key // deterministic order for same-ms writes
	})
	return out
}

// Read returns the thread's messages oldest-first and marks them read.
func (s *Store) Read(key string) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.threads[key]
	if !ok {
		return nil, fmt.Errorf("no conversation for %s", key)
	}
	out := make([]Message, len(t.Messages))
	copy(out, t.Messages)
	dirty := false
	for i := range t.Messages {
		if !t.Messages[i].IsRead {
			t.Messages[i].IsRead = true
			dirty = true
		}
	}
	if dirty {
		if err := s.saveLocked(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// UnreadTotal sums unread messages across every thread.
func (s *Store) UnreadTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.threads {
		n += t.unread()
	}
	return n
}
