// internal/registry/peers.go
//
// Peer/identity knowledge for the interactive shell.
//
// Before this file existed, the shell's Tab completion only ever offered peer
// IDs that happened to be keys in State.Mailbox. Mailbox is only written when
// a *message* is exchanged, so the two most common ways a peer ID enters a
// session were invisible to completion:
//
//   - the initiator typing `connect <peer-id>` (no mailbox entry is created
//     until that peer actually replies), and
//   - the responder receiving an offer during `listen` (the handshake creates
//     a session, but again no mailbox entry).
//
// The result was that a 44+ character base58 ID had to be retyped or pasted
// by hand for every subsequent send/mailbox/connect. KnownPeers fixes that by
// recording a peer ID the moment it is seen, from any direction, and by also
// surfacing the peers already persisted in the loaded identity's session map
// and every alias in the global contacts book.
package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/contacts"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// pendingPrefix marks the placeholder entries client.Client stores in its
// Sessions map while a handshake is in flight ("pending" and
// "pending_<peerID>"). They are not peers and must never be completed.
const pendingPrefix = "pending"

// ErrEmptyPeer is returned by ResolvePeer for blank input.
var ErrEmptyPeer = errors.New("empty peer id")

// AmbiguousPeerError is returned when a typed prefix matches several known
// peers. It carries the matches so the caller can show the user what to
// disambiguate between.
type AmbiguousPeerError struct {
	Input   string
	Matches []string
}

func (e *AmbiguousPeerError) Error() string {
	return fmt.Sprintf("ambiguous peer prefix %q matches %d known peers: %s",
		e.Input, len(e.Matches), strings.Join(shortIDs(e.Matches), ", "))
}

// RememberPeer records peerID as a peer this session knows about, so it
// becomes Tab-completable immediately. Safe to call repeatedly and with an
// empty or placeholder ID (both are ignored).
func (s *State) RememberPeer(peerID string) {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" || isPending(peerID) {
		return
	}
	if s.KnownPeers == nil {
		s.KnownPeers = make(map[string]bool)
	}
	s.KnownPeers[peerID] = true
}

// SyncPeersFromClient records every established session of the loaded identity
// as a known peer. Call this right after init/load so a restarted shell can
// complete the peers it talked to in a previous run.
func (s *State) SyncPeersFromClient() {
	if s.ActiveClient == nil {
		return
	}
	for id := range s.ActiveClient.Sessions {
		s.RememberPeer(id)
	}
}

// peerIDs is the set of real peer IDs (no aliases, no handshake placeholders)
// this session knows about, unioned across every source so a peer is known no
// matter how it arrived:
//
//  1. KnownPeers — anything seen this session (connect/offer/answer/message).
//  2. Mailbox    — peers with chat history.
//  3. Sessions   — peers persisted in the loaded identity's <id>.json, which
//     survives a restart.
func (s *State) peerIDs() map[string]bool {
	set := make(map[string]bool, len(s.KnownPeers)+len(s.Mailbox))
	add := func(id string) {
		if !isPending(id) {
			set[id] = true
		}
	}

	for id := range s.KnownPeers {
		add(id)
	}
	for id := range s.Mailbox {
		add(id)
	}
	if s.ActiveClient != nil {
		for id := range s.ActiveClient.Sessions {
			add(id)
		}
	}
	return set
}

// PeerCandidates returns everything meaningful to complete in a <peer> slot,
// sorted: every known peer ID plus every contacts alias and the ID it maps to.
//
// Aliases are included because every command that takes a peer resolves them
// via ResolvePeer, so an alias is a legal value in that slot.
func (s *State) PeerCandidates() []string {
	set := s.peerIDs()

	if book, err := contacts.Load(); err == nil {
		for name, c := range book.Contacts {
			if name != "" {
				set[name] = true
			}
			if c.UserID != "" {
				set[c.UserID] = true
			}
		}
	}

	// Never offer the user their own ID as a send/connect target.
	if s.ActiveClient != nil {
		delete(set, s.ActiveClient.Id)
	}

	return sortedKeys(set)
}

// IdentityCandidates returns the local identities that `load <id>` accepts: the
// base names of every "<peerID>.json" profile in the current working directory.
// client.SaveClient writes these as bare relative paths, so the CWD is the whole
// keystore. contacts.json is excluded — it's the address book, not an identity.
func (s *State) IdentityCandidates() []string {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil
	}

	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if id := strings.TrimSuffix(e.Name(), ".json"); id != "" && id != "contacts" {
			set[id] = true
		}
	}
	return sortedKeys(set)
}

// ResolvePeer turns whatever the user typed into a full peer ID.
//
// Resolution order is deliberately safety-first:
//
//  1. A contacts alias wins if it matches exactly — aliases are chosen by the
//     user, so an exact alias hit is unambiguous intent.
//  2. An exact known-peer ID wins next, so a fully typed/pasted ID is never
//     reinterpreted.
//  3. Only then is unique-prefix matching attempted, and it REFUSES to guess
//     when the prefix matches more than one known peer, returning an error
//     instead of silently picking one. Sending a message to the wrong peer
//     because of a truncated ID is a security failure, not a convenience bug.
//  4. If nothing matches at all, the input is returned verbatim so a user can
//     still address a peer they have never talked to.
func (s *State) ResolvePeer(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", ErrEmptyPeer
	}

	if book, err := contacts.Load(); err == nil {
		if c, ok := book.Contacts[input]; ok && c.UserID != "" {
			return c.UserID, nil
		}
	}

	// Aliases are excluded from prefix matching on purpose: prefix-matching a
	// human-chosen name against IDs would make ambiguity errors confusing.
	known := s.peerIDs()
	if known[input] {
		return input, nil
	}

	var matches []string
	for id := range known {
		if strings.HasPrefix(id, input) {
			matches = append(matches, id)
		}
	}

	switch len(matches) {
	case 0:
		// Unknown to us — treat as a literal full ID so a fresh peer can be
		// contacted before any session or mailbox entry exists.
		return input, nil
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", &AmbiguousPeerError{Input: input, Matches: matches}
	}
}

// PrintPeers lists everything Tab will complete in a <peer> slot. hint names
// the transport's own way of learning a peer, shown when nothing is known yet.
// Shared by every transport's `peers` command so the output can't diverge.
func (s *State) PrintPeers(hint string) {
	candidates := s.PeerCandidates()
	if len(candidates) == 0 {
		fmt.Printf("  %s No known peers yet — %s first.\n", ui.Info.Sprint("[i]"), hint)
		return
	}

	fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Completable peers ❖"))
	for _, p := range candidates {
		fmt.Printf("  %s\n", ui.Info.Sprint(p))
	}
	fmt.Println("\nAny of these completes with Tab in a <peer> slot.")
}

// ShortID trims a long ID for display only (e.g. 911ef9...4f28). Full IDs are
// always used for matching and lookup, so this never affects behaviour.
func ShortID(id string) string {
	if len(id) < 12 {
		return id
	}
	return id[:6] + "..." + id[len(id)-4:]
}

func shortIDs(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = ShortID(id)
	}
	return out
}

func isPending(key string) bool {
	return key == pendingPrefix || strings.HasPrefix(key, pendingPrefix+"_")
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
