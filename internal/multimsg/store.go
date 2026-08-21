// Package multimsg implements the multi-user message/fan-out layer for NexTalk.
package multimsg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
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
	return ctx, nil
}

func (s *MemoryContextStore) ListContexts() ([]*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*MessageContext, 0, len(s.contexts))
	for _, ctx := range s.contexts {
		out = append(out, ctx)
	}
	return out, nil
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

// Common errors
var (
	ErrContextNotFound  = &multimsgError{"context not found"}
	ErrPolicyNotFound   = &multimsgError{"policy not found"}
	ErrDeliveryNotFound = &multimsgError{"delivery not found"}
	ErrDeliveryPending  = &multimsgError{"delivery pending (no ciphertext yet)"}
)

type multimsgError struct {
	msg string
}

func (e *multimsgError) Error() string {
	return e.msg
}

// JSONContextStore provides file-based persistence using JSON.
// This is a simple implementation for CLI/offline use.
//
// SECURITY NOTE: This is NOT production-grade crash-safe storage. It uses
// simple write-to-file semantics without atomic rename, WAL, or fsync.
// A crash during write may corrupt the file. For production use, replace
// with SQLite or an append-only log with checksums.
type JSONContextStore struct {
	mu           sync.RWMutex
	contextsFile string
	policiesFile string
	contexts     map[ContextID]*MessageContext
	policies     map[ContextID]map[string]*LocalRecipientPolicy
}

// NewJSONContextStore creates a new JSON-backed context store.
func NewJSONContextStore(contextsFile, policiesFile string) (*JSONContextStore, error) {
	s := &JSONContextStore{
		contextsFile: contextsFile,
		policiesFile: policiesFile,
		contexts:     make(map[ContextID]*MessageContext),
		policies:     make(map[ContextID]map[string]*LocalRecipientPolicy),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// jsonContext is the serializable form of MessageContext.
type jsonContext struct {
	ContextID       string `json:"context_id"`
	DisplayName     string `json:"display_name"`
	MetadataVersion uint64 `json:"metadata_version"`
	CreatorID       string `json:"creator_id"`
	Signature       string `json:"signature"` // base64
}

func ctxToJSON(ctx *MessageContext) jsonContext {
	return jsonContext{
		ContextID:       string(ctx.ContextID),
		DisplayName:     ctx.DisplayName,
		MetadataVersion: ctx.MetadataVersion,
		CreatorID:       ctx.CreatorID,
		Signature:       base64.StdEncoding.EncodeToString(ctx.Signature),
	}
}

func ctxFromJSON(j jsonContext) (*MessageContext, error) {
	sig, err := base64.StdEncoding.DecodeString(j.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return &MessageContext{
		ContextID:       ContextID(j.ContextID),
		DisplayName:     j.DisplayName,
		MetadataVersion: j.MetadataVersion,
		CreatorID:       j.CreatorID,
		Signature:       sig,
	}, nil
}

func (s *JSONContextStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load contexts
	if data, err := os.ReadFile(s.contextsFile); err == nil {
		var contexts []jsonContext
		if err := json.Unmarshal(data, &contexts); err != nil {
			return fmt.Errorf("parse contexts file: %w", err)
		}
		for _, j := range contexts {
			ctx, err := ctxFromJSON(j)
			if err != nil {
				// Skip corrupted entries but log
				continue
			}
			// Validate version
			if ctx.MetadataVersion == 0 {
				continue // Skip invalid
			}
			s.contexts[ctx.ContextID] = ctx
		}
	}

	// Load policies
	if data, err := os.ReadFile(s.policiesFile); err == nil {
		var policies []jsonPolicy
		if err := json.Unmarshal(data, &policies); err != nil {
			return fmt.Errorf("parse policies file: %w", err)
		}
		for _, j := range policies {
			if s.policies[ContextID(j.ContextID)] == nil {
				s.policies[ContextID(j.ContextID)] = make(map[string]*LocalRecipientPolicy)
			}
			s.policies[ContextID(j.ContextID)][j.Recipient] = &LocalRecipientPolicy{
				ContextID: ContextID(j.ContextID),
				Recipient: j.Recipient,
				Policy:    RecipientPolicy(j.Policy),
				UpdatedAt: j.UpdatedAt,
			}
		}
	}

	return nil
}

func (s *JSONContextStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Save contexts
	contexts := make([]jsonContext, 0, len(s.contexts))
	for _, ctx := range s.contexts {
		contexts = append(contexts, ctxToJSON(ctx))
	}
	if data, err := json.MarshalIndent(contexts, "", "  "); err == nil {
		// Write to temp file first, then rename for atomicity
		tmpFile := s.contextsFile + ".tmp"
		if err := os.WriteFile(tmpFile, data, 0600); err == nil {
			os.Rename(tmpFile, s.contextsFile)
		}
	}

	// Save policies
	policies := make([]jsonPolicy, 0)
	for ctxID, pols := range s.policies {
		for recipient, pol := range pols {
			policies = append(policies, jsonPolicy{
				ContextID: string(ctxID),
				Recipient: recipient,
				Policy:    int(pol.Policy),
				UpdatedAt: pol.UpdatedAt,
			})
		}
	}
	if data, err := json.MarshalIndent(policies, "", "  "); err == nil {
		tmpFile := s.policiesFile + ".tmp"
		if err := os.WriteFile(tmpFile, data, 0600); err == nil {
			os.Rename(tmpFile, s.policiesFile)
		}
	}

	return nil
}

// jsonPolicy is the serializable form of LocalRecipientPolicy.
type jsonPolicy struct {
	ContextID string `json:"context_id"`
	Recipient string `json:"recipient"`
	Policy    int    `json:"policy"`
	UpdatedAt int64  `json:"updated_at"`
}

func (s *JSONContextStore) SaveContext(ctx *MessageContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Version check: don't overwrite newer with older
	if existing, ok := s.contexts[ctx.ContextID]; ok {
		if ctx.MetadataVersion <= existing.MetadataVersion {
			return fmt.Errorf("stale context: version %d <= existing %d",
				ctx.MetadataVersion, existing.MetadataVersion)
		}
	}

	s.contexts[ctx.ContextID] = ctx
	s.mu.Unlock()
	err := s.save()
	s.mu.Lock()
	return err
}

func (s *JSONContextStore) LoadContext(id ContextID) (*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctx, ok := s.contexts[id]
	if !ok {
		return nil, ErrContextNotFound
	}
	return ctx, nil
}

func (s *JSONContextStore) ListContexts() ([]*MessageContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*MessageContext, 0, len(s.contexts))
	for _, ctx := range s.contexts {
		out = append(out, ctx)
	}
	return out, nil
}

func (s *JSONContextStore) DeleteContext(id ContextID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, id)
	delete(s.policies, id)
	return s.save()
}

func (s *JSONContextStore) SavePolicy(policy *LocalRecipientPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policies[policy.ContextID] == nil {
		s.policies[policy.ContextID] = make(map[string]*LocalRecipientPolicy)
	}
	s.policies[policy.ContextID][policy.Recipient] = policy
	return s.save()
}

func (s *JSONContextStore) LoadPolicy(contextID ContextID, recipient string) (*LocalRecipientPolicy, error) {
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

func (s *JSONContextStore) ListPolicies(contextID ContextID) ([]*LocalRecipientPolicy, error) {
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
	return out, nil
}

func (s *JSONContextStore) DeletePolicy(contextID ContextID, recipient string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctxPolicies, ok := s.policies[contextID]; ok {
		delete(ctxPolicies, recipient)
	}
	return s.save()
}

// JSONDeliveryStore provides file-based persistence for deliveries.
//
// SECURITY NOTE: This is NOT production-grade crash-safe storage. See
// JSONContextStore for the same limitations.
type JSONDeliveryStore struct {
	mu             sync.RWMutex
	deliveriesFile string
	deliveries     map[DeliveryID]*MessageDelivery
	byMessage      map[MessageID][]DeliveryID
	byRecipient    map[string][]DeliveryID
}

// NewJSONDeliveryStore creates a new JSON-backed delivery store.
func NewJSONDeliveryStore(deliveriesFile string) (*JSONDeliveryStore, error) {
	s := &JSONDeliveryStore{
		deliveriesFile: deliveriesFile,
		deliveries:     make(map[DeliveryID]*MessageDelivery),
		byMessage:      make(map[MessageID][]DeliveryID),
		byRecipient:    make(map[string][]DeliveryID),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// jsonDelivery is the serializable form of MessageDelivery.
type jsonDelivery struct {
	DeliveryID string `json:"delivery_id"`
	MessageID  string `json:"message_id"`
	Recipient  string `json:"recipient"`
	ChannelID  string `json:"channel_id"`
	Ciphertext string `json:"ciphertext"` // base64
	ContextID  string `json:"context_id"`
	Timestamp  int64  `json:"timestamp"`
}

func deliveryToJSON(d *MessageDelivery) jsonDelivery {
	return jsonDelivery{
		DeliveryID: string(d.DeliveryID),
		MessageID:  string(d.MessageID),
		Recipient:  d.Recipient,
		ChannelID:  d.ChannelID,
		Ciphertext: base64.StdEncoding.EncodeToString(d.Ciphertext),
		ContextID:  string(d.ContextID),
		Timestamp:  d.Timestamp,
	}
}

func deliveryFromJSON(j jsonDelivery) (*MessageDelivery, error) {
	var ciphertext []byte
	if j.Ciphertext != "" {
		var err error
		ciphertext, err = base64.StdEncoding.DecodeString(j.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decode ciphertext: %w", err)
		}
	}
	return &MessageDelivery{
		DeliveryID: DeliveryID(j.DeliveryID),
		MessageID:  MessageID(j.MessageID),
		Recipient:  j.Recipient,
		ChannelID:  j.ChannelID,
		Ciphertext: ciphertext,
		ContextID:  ContextID(j.ContextID),
		Timestamp:  j.Timestamp,
	}, nil
}

func (s *JSONDeliveryStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if data, err := os.ReadFile(s.deliveriesFile); err == nil {
		var deliveries []jsonDelivery
		if err := json.Unmarshal(data, &deliveries); err != nil {
			return fmt.Errorf("parse deliveries file: %w", err)
		}
		for _, j := range deliveries {
			d, err := deliveryFromJSON(j)
			if err != nil {
				continue // Skip corrupted entries
			}
			s.deliveries[d.DeliveryID] = d
			s.byMessage[d.MessageID] = append(s.byMessage[d.MessageID], d.DeliveryID)
			s.byRecipient[d.Recipient] = append(s.byRecipient[d.Recipient], d.DeliveryID)
		}
	}

	return nil
}

func (s *JSONDeliveryStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	deliveries := make([]jsonDelivery, 0, len(s.deliveries))
	for _, d := range s.deliveries {
		deliveries = append(deliveries, deliveryToJSON(d))
	}
	if data, err := json.MarshalIndent(deliveries, "", "  "); err == nil {
		tmpFile := s.deliveriesFile + ".tmp"
		if err := os.WriteFile(tmpFile, data, 0600); err == nil {
			os.Rename(tmpFile, s.deliveriesFile)
		}
	}

	return nil
}

func (s *JSONDeliveryStore) SaveDelivery(d *MessageDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate delivery ID
	if _, exists := s.deliveries[d.DeliveryID]; exists {
		return fmt.Errorf("duplicate delivery ID: %s", d.DeliveryID)
	}

	s.deliveries[d.DeliveryID] = d
	s.byMessage[d.MessageID] = append(s.byMessage[d.MessageID], d.DeliveryID)
	s.byRecipient[d.Recipient] = append(s.byRecipient[d.Recipient], d.DeliveryID)
	return s.save()
}

func (s *JSONDeliveryStore) LoadDelivery(id DeliveryID) (*MessageDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deliveries[id]
	if !ok {
		return nil, ErrDeliveryNotFound
	}
	return d, nil
}

func (s *JSONDeliveryStore) ListDeliveriesByMessage(msgID MessageID) ([]*MessageDelivery, error) {
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

func (s *JSONDeliveryStore) ListDeliveriesByRecipient(recipient string) ([]*MessageDelivery, error) {
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

func (s *JSONDeliveryStore) ListUndeliveredDeliveries() ([]*MessageDelivery, error) {
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

func (s *JSONDeliveryStore) MarkDelivered(id DeliveryID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.deliveries[id]
	if !ok {
		return ErrDeliveryNotFound
	}
	if d.Ciphertext == nil {
		return ErrDeliveryPending
	}
	return s.save()
}
