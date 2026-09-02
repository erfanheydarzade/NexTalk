// Package multimsg implements the multi-user message/fan-out layer for NexTalk.
package multimsg

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/erfanheydarzade/NexTalk/internal/binstore"
	"github.com/erfanheydarzade/nanopack"
)

// MemoryContextStore is an in-memory implementation of ContextStore for testing.
type MemoryContextStore struct {
	mu       sync.RWMutex
	contexts map[ContextID]*MessageContext
	policies map[ContextID]map[string]*LocalRecipientPolicy
}

// NewMemoryContextStore creates a new in-memory context store.
func NewMemoryContextStore() *MemoryContextStore {
	return &MemoryContextStore{
		contexts: make(map[ContextID]*MessageContext),
		policies: make(map[ContextID]map[string]*LocalRecipientPolicy),
	}
}

func (s *MemoryContextStore) SaveContext(ctx *MessageContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[ctx.ContextID] = ctx
	return nil
}

func (s *MemoryContextStore) LoadContext(id ContextID) (*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctx, ok := s.contexts[id]
	if !ok {
		return nil, ErrContextNotFound
	}
	cp := *ctx // never hand out the internal pointer — callers mutate freely
	return &cp, nil
}

func (s *MemoryContextStore) ListContexts() ([]*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*MessageContext, 0, len(s.contexts))
	for _, ctx := range s.contexts {
		cp := *ctx
		out = append(out, &cp)
	}
	sortContexts(out)
	return out, nil
}

// sortContexts orders contexts deterministically (by ID) so listings and
// scripted output never depend on map iteration order.
func sortContexts(ctxs []*MessageContext) {
	sort.Slice(ctxs, func(i, j int) bool { return ctxs[i].ContextID < ctxs[j].ContextID })
}

// sortPolicies orders policies deterministically (by recipient).
func sortPolicies(pols []*LocalRecipientPolicy) {
	sort.Slice(pols, func(i, j int) bool { return pols[i].Recipient < pols[j].Recipient })
}

func (s *MemoryContextStore) DeleteContext(id ContextID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, id)
	delete(s.policies, id)
	return nil
}

func (s *MemoryContextStore) SavePolicy(policy *LocalRecipientPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policies[policy.ContextID] == nil {
		s.policies[policy.ContextID] = make(map[string]*LocalRecipientPolicy)
	}
	s.policies[policy.ContextID][policy.Recipient] = policy
	return nil
}

func (s *MemoryContextStore) LoadPolicy(contextID ContextID, recipient string) (*LocalRecipientPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctxPolicies, ok := s.policies[contextID]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	policy, ok := ctxPolicies[recipient]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	return policy, nil
}

func (s *MemoryContextStore) ListPolicies(contextID ContextID) ([]*LocalRecipientPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctxPolicies, ok := s.policies[contextID]
	if !ok {
		return nil, nil
	}
	out := make([]*LocalRecipientPolicy, 0, len(ctxPolicies))
	for _, p := range ctxPolicies {
		out = append(out, p)
	}
	sortPolicies(out)
	return out, nil
}

func (s *MemoryContextStore) DeletePolicy(contextID ContextID, recipient string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctxPolicies, ok := s.policies[contextID]; ok {
		delete(ctxPolicies, recipient)
	}
	return nil
}

// MemoryDeliveryStore is an in-memory implementation of DeliveryStore for testing.
type MemoryDeliveryStore struct {
	mu          sync.RWMutex
	deliveries  map[DeliveryID]*MessageDelivery
	byMessage   map[MessageID][]DeliveryID
	byRecipient map[string][]DeliveryID
}

// NewMemoryDeliveryStore creates a new in-memory delivery store.
func NewMemoryDeliveryStore() *MemoryDeliveryStore {
	return &MemoryDeliveryStore{
		deliveries:  make(map[DeliveryID]*MessageDelivery),
		byMessage:   make(map[MessageID][]DeliveryID),
		byRecipient: make(map[string][]DeliveryID),
	}
}

func (s *MemoryDeliveryStore) SaveDelivery(d *MessageDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries[d.DeliveryID] = d
	s.byMessage[d.MessageID] = append(s.byMessage[d.MessageID], d.DeliveryID)
	s.byRecipient[d.Recipient] = append(s.byRecipient[d.Recipient], d.DeliveryID)
	return nil
}

func (s *MemoryDeliveryStore) LoadDelivery(id DeliveryID) (*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deliveries[id]
	if !ok {
		return nil, ErrDeliveryNotFound
	}
	return d, nil
}

func (s *MemoryDeliveryStore) ListDeliveriesByMessage(msgID MessageID) ([]*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids, ok := s.byMessage[msgID]
	if !ok {
		return nil, nil
	}
	out := make([]*MessageDelivery, 0, len(ids))
	for _, id := range ids {
		if d, ok := s.deliveries[id]; ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *MemoryDeliveryStore) ListDeliveriesByRecipient(recipient string) ([]*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids, ok := s.byRecipient[recipient]
	if !ok {
		return nil, nil
	}
	out := make([]*MessageDelivery, 0, len(ids))
	for _, id := range ids {
		if d, ok := s.deliveries[id]; ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *MemoryDeliveryStore) ListUndeliveredDeliveries() ([]*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*MessageDelivery
	for _, d := range s.deliveries {
		if d.Ciphertext == nil {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *MemoryDeliveryStore) MarkDelivered(id DeliveryID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[id]
	if !ok {
		return ErrDeliveryNotFound
	}
	// In a real implementation, we'd track delivery status separately
	// For now, just ensure it has ciphertext
	if d.Ciphertext == nil {
		return ErrDeliveryPending
	}
	return nil
}

// -- File-backed stores (nanopack binary via internal/binstore) ----------------
//
// Contexts, policies and deliveries persist per identity as CRC-framed
// nanopack record files (<id>.contexts.np / <id>.policies.np /
// <id>.deliveries.np). The pre-nanopack *.json layouts remain readable for
// one-time migration; every write goes to the .np file.

// OpenIdentityStores opens the standard per-identity context/policy and
// delivery stores. Every caller — shell init/load, CLI commands, listen
// dispatch — uses this one constructor so the file layout has a single
// definition point.
func OpenIdentityStores(identityID string) (ContextStore, DeliveryStore, error) {
	ctxStore, err := NewFileContextStore(
		identityID+".contexts.json",
		identityID+".policies.json",
	)
	if err != nil {
		return nil, nil, err
	}
	deliveryStore, err := NewFileDeliveryStore(identityID + ".deliveries.json")
	if err != nil {
		return nil, nil, err
	}
	return ctxStore, deliveryStore, nil
}

// policyBin is the nanopack record shape of a LocalRecipientPolicy.
//
//nanopack:schema id=44
type policyBin struct {
	ContextID string `bin:"1"`
	Recipient string `bin:"2"`
	Policy    uint8  `bin:"3"`
	UpdatedAt uint64 `bin:"4"`
}

func (p *policyBin) MarshalBinID(e *nanopack.Encoder) error {
	e.AddID(1, []byte(p.ContextID))
	e.AddID(2, []byte(p.Recipient))
	e.AddID(3, []byte{p.Policy})
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], p.UpdatedAt)
	e.AddID(4, ts[:])
	return nil
}

func (p *policyBin) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case 1:
			p.ContextID = string(f.Data)
		case 2:
			p.Recipient = string(f.Data)
		case 3:
			if len(f.Data) == 1 {
				p.Policy = f.Data[0]
			}
		case 4:
			if len(f.Data) == 8 {
				p.UpdatedAt = binary.BigEndian.Uint64(f.Data)
			}
		}
	}
	return nil
}

func policyToRecord(p *LocalRecipientPolicy) ([]byte, error) {
	return nanopack.MarshalFastID(&policyBin{
		ContextID: string(p.ContextID),
		Recipient: p.Recipient,
		Policy:    uint8(p.Policy),
		UpdatedAt: uint64(p.UpdatedAt),
	})
}

func policyFromRecord(rec []byte) (*LocalRecipientPolicy, error) {
	var pb policyBin
	if err := nanopack.UnmarshalFastID(rec, &pb); err != nil {
		return nil, err
	}
	return &LocalRecipientPolicy{
		ContextID: ContextID(pb.ContextID),
		Recipient: pb.Recipient,
		Policy:    RecipientPolicy(pb.Policy),
		UpdatedAt: int64(pb.UpdatedAt),
	}, nil
}

// npPath maps a legacy ".json" path to its nanopack successor.
func npPath(path string) string {
	return strings.TrimSuffix(path, ".json") + ".np"
}

// FileContextStore persists contexts and local recipient policies.
type FileContextStore struct {
	mu           sync.RWMutex
	contextsFile string // .np path; the given path is kept as legacy source
	policiesFile string
	contexts     map[ContextID]*MessageContext
	policies     map[ContextID]map[string]*LocalRecipientPolicy
}

// NewFileContextStore creates a context store backed by nanopack files.
// The arguments are the historical ".json" paths; data now lives at the
// corresponding ".np" paths and the old files are READ once for migration.
func NewFileContextStore(contextsFile, policiesFile string) (*FileContextStore, error) {
	s := &FileContextStore{
		contextsFile: npPath(contextsFile),
		policiesFile: npPath(policiesFile),
		contexts:     make(map[ContextID]*MessageContext),
		policies:     make(map[ContextID]map[string]*LocalRecipientPolicy),
	}
	if err := s.load(contextsFile, policiesFile); err != nil {
		return nil, err
	}
	return s, nil
}

// Deprecated: use NewFileContextStore.
func NewJSONContextStore(contextsFile, policiesFile string) (*FileContextStore, error) {
	return NewFileContextStore(contextsFile, policiesFile)
}

// loadContextsRecords reads contexts+policy records from .np files, falling
// back to the legacy JSON files for a one-time migration.
func (s *FileContextStore) load(legacyContextsFile, legacyPoliciesFile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctxLoaded := false
	if records, err := binstore.Load(s.contextsFile, MessageContextSchemaID); err == nil {
		for _, rec := range records {
			ctx := &MessageContext{}
			if nanopack.UnmarshalFastID(rec, ctx) != nil || ctx.MetadataVersion == 0 {
				continue
			}
			s.contexts[ctx.ContextID] = ctx
		}
		ctxLoaded = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", s.contextsFile, err)
	}

	polLoaded := false
	if records, err := binstore.Load(s.policiesFile, PolicySchemaID); err == nil {
		for _, rec := range records {
			pol, err := policyFromRecord(rec)
			if err != nil {
				continue
			}
			s.insertPolicyLocked(pol)
		}
		polLoaded = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", s.policiesFile, err)
	}

	if ctxLoaded && polLoaded {
		return nil
	}

	// Legacy migration from the original JSON layout.
	if !ctxLoaded {
		if data, err := os.ReadFile(legacyContextsFile); err == nil {
			var raw []struct {
				ContextID       string `json:"context_id"`
				DisplayName     string `json:"display_name"`
				MetadataVersion uint64 `json:"metadata_version"`
				CreatorID       string `json:"creator_id"`
				Signature       []byte `json:"signature"`
			}
			if json.Unmarshal(data, &raw) == nil {
				for _, j := range raw {
					if j.MetadataVersion == 0 {
						continue
					}
					ctx := &MessageContext{
						ContextID:       ContextID(j.ContextID),
						DisplayName:     j.DisplayName,
						MetadataVersion: j.MetadataVersion,
						CreatorID:       j.CreatorID,
						Signature:       j.Signature,
					}
					s.contexts[ctx.ContextID] = ctx
				}
			}
		}
	}
	if !polLoaded {
		if data, err := os.ReadFile(legacyPoliciesFile); err == nil {
			var raw []struct {
				ContextID string `json:"context_id"`
				Recipient string `json:"recipient"`
				Policy    int    `json:"policy"`
				UpdatedAt int64  `json:"updated_at"`
			}
			if json.Unmarshal(data, &raw) == nil {
				for _, j := range raw {
					s.insertPolicyLocked(&LocalRecipientPolicy{
						ContextID: ContextID(j.ContextID),
						Recipient: j.Recipient,
						Policy:    RecipientPolicy(j.Policy),
						UpdatedAt: j.UpdatedAt,
					})
				}
			}
		}
	}
	_ = s.saveLocked()
	return nil
}

func (s *FileContextStore) insertPolicyLocked(p *LocalRecipientPolicy) {
	if s.policies[p.ContextID] == nil {
		s.policies[p.ContextID] = make(map[string]*LocalRecipientPolicy)
	}
	s.policies[p.ContextID][p.Recipient] = p
}

// saveLocked writes both files. Caller holds s.mu (any lock level).
func (s *FileContextStore) saveLocked() error {
	contexts := make([][]byte, 0, len(s.contexts))
	for _, ctx := range s.contexts {
		rec, err := nanopack.MarshalFastID(ctx)
		if err != nil {
			return err
		}
		contexts = append(contexts, rec)
	}
	if err := binstore.Save(s.contextsFile, MessageContextSchemaID, contexts); err != nil {
		return err
	}

	policies := make([][]byte, 0, 16)
	for _, pols := range s.policies {
		for _, p := range pols {
			rec, err := policyToRecord(p)
			if err != nil {
				return err
			}
			policies = append(policies, rec)
		}
	}
	return binstore.Save(s.policiesFile, PolicySchemaID, policies)
}

func (s *FileContextStore) SaveContext(ctx *MessageContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Version check: don't overwrite newer with older
	if existing, ok := s.contexts[ctx.ContextID]; ok {
		if ctx.MetadataVersion <= existing.MetadataVersion {
			return fmt.Errorf("stale context: version %d <= existing %d",
				ctx.MetadataVersion, existing.MetadataVersion)
		}
	}

	cp := *ctx
	s.contexts[cp.ContextID] = &cp
	return s.saveLocked()
}

func (s *FileContextStore) LoadContext(id ContextID) (*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctx, ok := s.contexts[id]
	if !ok {
		return nil, ErrContextNotFound
	}
	cp := *ctx // never hand out the internal pointer � callers mutate freely
	return &cp, nil
}

func (s *FileContextStore) ListContexts() ([]*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*MessageContext, 0, len(s.contexts))
	for _, ctx := range s.contexts {
		cp := *ctx
		out = append(out, &cp)
	}
	return out, nil
}

func (s *FileContextStore) DeleteContext(id ContextID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, id)
	delete(s.policies, id)
	return s.saveLocked()
}

func (s *FileContextStore) SavePolicy(policy *LocalRecipientPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *policy
	s.insertPolicyLocked(&cp)
	return s.saveLocked()
}

func (s *FileContextStore) LoadPolicy(contextID ContextID, recipient string) (*LocalRecipientPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctxPolicies, ok := s.policies[contextID]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	policy, ok := ctxPolicies[recipient]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	cp := *policy
	return &cp, nil
}

func (s *FileContextStore) ListPolicies(contextID ContextID) ([]*LocalRecipientPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctxPolicies, ok := s.policies[contextID]
	if !ok {
		return nil, nil
	}
	out := make([]*LocalRecipientPolicy, 0, len(ctxPolicies))
	for _, p := range ctxPolicies {
		cp := *p
		out = append(out, &cp)
	}
	sortPolicies(out)
	return out, nil
}

func (s *FileContextStore) DeletePolicy(contextID ContextID, recipient string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctxPolicies, ok := s.policies[contextID]; ok {
		delete(ctxPolicies, recipient)
	}
	return s.saveLocked()
}

// FileDeliveryStore persists multi-message deliveries.
type FileDeliveryStore struct {
	mu             sync.RWMutex
	deliveriesFile string // .np path; the given path is kept as legacy source
	deliveries     map[DeliveryID]*MessageDelivery
	byMessage      map[MessageID][]DeliveryID
	byRecipient    map[string][]DeliveryID
}

// NewFileDeliveryStore creates a delivery store backed by a nanopack file.
func NewFileDeliveryStore(deliveriesFile string) (*FileDeliveryStore, error) {
	s := &FileDeliveryStore{
		deliveriesFile: npPath(deliveriesFile),
		deliveries:     make(map[DeliveryID]*MessageDelivery),
		byMessage:      make(map[MessageID][]DeliveryID),
		byRecipient:    make(map[string][]DeliveryID),
	}

	records, err := binstore.Load(s.deliveriesFile, MessageDeliverySchemaID)
	switch {
	case err == nil:
		for _, rec := range records {
			d := &MessageDelivery{}
			if nanopack.UnmarshalFastID(rec, d) != nil {
				continue
			}
			s.indexLocked(d)
		}
		return s, nil
	case errors.Is(err, os.ErrNotExist):
		// fall through to legacy migration
	default:
		return nil, fmt.Errorf("read %s: %w", s.deliveriesFile, err)
	}

	if data, err := os.ReadFile(deliveriesFile); err == nil {
		var raw []struct {
			DeliveryID string `json:"delivery_id"`
			MessageID  string `json:"message_id"`
			Recipient  string `json:"recipient"`
			ChannelID  string `json:"channel_id"`
			Ciphertext []byte `json:"ciphertext"`
			ContextID  string `json:"context_id"`
			Timestamp  int64  `json:"timestamp"`
		}
		if json.Unmarshal(data, &raw) == nil {
			for _, j := range raw {
				s.indexLocked(&MessageDelivery{
					DeliveryID: DeliveryID(j.DeliveryID),
					MessageID:  MessageID(j.MessageID),
					Recipient:  j.Recipient,
					ChannelID:  j.ChannelID,
					Ciphertext: j.Ciphertext,
					ContextID:  ContextID(j.ContextID),
					Timestamp:  j.Timestamp,
				})
			}
		}
		_ = s.saveLocked()
	}
	return s, nil
}

// Deprecated: use NewFileDeliveryStore.
func NewJSONDeliveryStore(deliveriesFile string) (*FileDeliveryStore, error) {
	return NewFileDeliveryStore(deliveriesFile)
}

func (s *FileDeliveryStore) indexLocked(d *MessageDelivery) {
	if _, exists := s.deliveries[d.DeliveryID]; exists {
		return
	}
	s.deliveries[d.DeliveryID] = d
	s.byMessage[d.MessageID] = append(s.byMessage[d.MessageID], d.DeliveryID)
	s.byRecipient[d.Recipient] = append(s.byRecipient[d.Recipient], d.DeliveryID)
}

func (s *FileDeliveryStore) saveLocked() error {
	records := make([][]byte, 0, len(s.deliveries))
	for _, d := range s.deliveries {
		rec, err := nanopack.MarshalFastID(d)
		if err != nil {
			return err
		}
		records = append(records, rec)
	}
	return binstore.Save(s.deliveriesFile, MessageDeliverySchemaID, records)
}

func (s *FileDeliveryStore) SaveDelivery(d *MessageDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.deliveries[d.DeliveryID]; exists {
		return fmt.Errorf("duplicate delivery ID: %s", d.DeliveryID)
	}
	s.deliveries[d.DeliveryID] = d
	s.byMessage[d.MessageID] = append(s.byMessage[d.MessageID], d.DeliveryID)
	s.byRecipient[d.Recipient] = append(s.byRecipient[d.Recipient], d.DeliveryID)
	return s.saveLocked()
}

func (s *FileDeliveryStore) LoadDelivery(id DeliveryID) (*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deliveries[id]
	if !ok {
		return nil, ErrDeliveryNotFound
	}
	cp := *d
	return &cp, nil
}

func (s *FileDeliveryStore) ListDeliveriesByMessage(msgID MessageID) ([]*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids, ok := s.byMessage[msgID]
	if !ok {
		return nil, nil
	}
	out := make([]*MessageDelivery, 0, len(ids))
	for _, id := range ids {
		if d, ok := s.deliveries[id]; ok {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *FileDeliveryStore) ListDeliveriesByRecipient(recipient string) ([]*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids, ok := s.byRecipient[recipient]
	if !ok {
		return nil, nil
	}
	out := make([]*MessageDelivery, 0, len(ids))
	for _, id := range ids {
		if d, ok := s.deliveries[id]; ok {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *FileDeliveryStore) ListUndeliveredDeliveries() ([]*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*MessageDelivery
	for _, d := range s.deliveries {
		if d.Ciphertext == nil {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *FileDeliveryStore) MarkDelivered(id DeliveryID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[id]
	if !ok {
		return ErrDeliveryNotFound
	}
	if d.Ciphertext == nil {
		return ErrDeliveryPending
	}
	return s.saveLocked()
}

// -- Common errors & helpers --------------------------------------------------

var (
	ErrContextNotFound   = &multimsgError{"context not found"}
	ErrPolicyNotFound    = &multimsgError{"policy not found"}
	ErrDeliveryNotFound  = &multimsgError{"delivery not found"}
	ErrDeliveryPending   = &multimsgError{"delivery pending (no ciphertext yet)"}
	ErrDuplicateDelivery = &multimsgError{"duplicate delivery"}
)

type multimsgError struct {
	msg string
}

func (e *multimsgError) Error() string {
	return e.msg
}

// shortPeer truncates a peer/context ID for compact display or logs.
func shortPeer(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
