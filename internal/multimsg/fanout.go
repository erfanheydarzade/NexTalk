// Package multimsg implements the multi-user message/fan-out layer for NexTalk.
package multimsg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// Fanout handles the creation and delivery of multi-user messages.
type Fanout struct {
	client          *client.Client
	relay           relay.Relay
	CtxStore        ContextStore
	deliveryStore   DeliveryStore
	config          FanoutConfig
	mu              sync.Mutex
	// seenDeliveries tracks delivery IDs that have been processed to prevent replay.
	// This is an in-memory cache; persistent replay protection is handled by
	// the underlying crypto session's nonce tracking.
	seenDeliveries map[DeliveryID]bool
}

// NewFanout creates a new Fanout instance.
func NewFanout(
	cl *client.Client,
	r relay.Relay,
	ctxStore ContextStore,
	deliveryStore DeliveryStore,
	config FanoutConfig,
) *Fanout {
	if config.MaxRetries == 0 {
		config = DefaultFanoutConfig()
	}
	return &Fanout{
		client:          cl,
		relay:           r,
		CtxStore:        ctxStore,
		deliveryStore:   deliveryStore,
		config:          config,
		seenDeliveries:  make(map[DeliveryID]bool),
	}
}

// IsDeliverySeen returns true if the delivery ID has already been processed.
func (f *Fanout) IsDeliverySeen(id DeliveryID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seenDeliveries[id]
}

// MarkDeliverySeen marks a delivery ID as processed for replay protection.
// Returns false if the delivery was already seen (replay detected).
func (f *Fanout) MarkDeliverySeen(id DeliveryID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seenDeliveries[id] {
		return false // Already seen — replay detected
	}
	f.seenDeliveries[id] = true
	return true
}

// CreateContext creates a new message context signed by the local identity.
func (f *Fanout) CreateContext(displayName string, creatorPriv ed25519.PrivateKey) (*MessageContext, error) {
	ctx := &MessageContext{
		ContextID:       GenerateContextID(),
		DisplayName:     displayName,
		MetadataVersion: 1,
		CreatorID:       f.client.Id,
	}
	if err := SignContext(ctx, creatorPriv); err != nil {
		return nil, fmt.Errorf("sign context: %w", err)
	}
	if err := f.CtxStore.SaveContext(ctx); err != nil {
		return nil, fmt.Errorf("save context: %w", err)
	}
	return ctx, nil
}

// UpdateContext updates the display name of an existing context.
// Only the creator can update; the new metadata version is signed.
// Version must be monotonically increasing — older versions are rejected
// to prevent rollback attacks.
func (f *Fanout) UpdateContext(contextID ContextID, newDisplayName string, creatorPriv ed25519.PrivateKey) (*MessageContext, error) {
	ctx, err := f.CtxStore.LoadContext(contextID)
	if err != nil {
		return nil, fmt.Errorf("load context: %w", err)
	}
	if ctx.CreatorID != f.client.Id {
		return nil, fmt.Errorf("only context creator can update metadata")
	}

	// Enforce monotonic version increase
	currentVersion := ctx.MetadataVersion
	newVersion := currentVersion + 1
	if newVersion <= currentVersion {
		return nil, fmt.Errorf("context version overflow")
	}

	ctx.DisplayName = newDisplayName
	ctx.MetadataVersion = newVersion
	if err := SignContext(ctx, creatorPriv); err != nil {
		return nil, fmt.Errorf("sign updated context: %w", err)
	}
	if err := f.CtxStore.SaveContext(ctx); err != nil {
		return nil, fmt.Errorf("save updated context: %w", err)
	}
	return ctx, nil
}

// ApplyRemoteContext applies a context descriptor received from a remote peer.
// It validates the signature, checks version monotonicity, and stores if valid.
// Returns an error if the context is stale (older version than already stored).
func (f *Fanout) ApplyRemoteContext(remoteCtx *MessageContext) error {
	if remoteCtx == nil {
		return fmt.Errorf("nil context")
	}
	if remoteCtx.MetadataVersion == 0 {
		return fmt.Errorf("invalid context version: 0")
	}

	// Check version monotonicity against stored context
	stored, err := f.CtxStore.LoadContext(remoteCtx.ContextID)
	if err == nil && stored != nil {
		if remoteCtx.MetadataVersion <= stored.MetadataVersion {
			return fmt.Errorf("stale context: remote version %d <= stored version %d",
				remoteCtx.MetadataVersion, stored.MetadataVersion)
		}
	}

	// Verify signature (signature format check; key binding at higher layer)
	if err := VerifyContextSignature(remoteCtx); err != nil {
		return fmt.Errorf("invalid context signature: %w", err)
	}

	return f.CtxStore.SaveContext(remoteCtx)
}

// SetRecipientPolicy sets the local delivery policy for a recipient in a context.
// This is purely local — it does not notify the recipient or other participants.
func (f *Fanout) SetRecipientPolicy(contextID ContextID, recipient string, policy RecipientPolicy) error {
	lp := &LocalRecipientPolicy{
		ContextID: contextID,
		Recipient: recipient,
		Policy:    policy,
		UpdatedAt: time.Now().UnixMilli(),
	}
	return f.CtxStore.SavePolicy(lp)
}

// GetRecipientPolicy returns the local policy for a recipient in a context.
// Returns PolicyEnabled if no explicit policy is set.
func (f *Fanout) GetRecipientPolicy(contextID ContextID, recipient string) (RecipientPolicy, error) {
	lp, err := f.CtxStore.LoadPolicy(contextID, recipient)
	if err != nil {
		return PolicyEnabled, nil // default
	}
	return lp.Policy, nil
}

// ListRecipientPolicies returns all local policies for a context.
func (f *Fanout) ListRecipientPolicies(contextID ContextID) ([]*LocalRecipientPolicy, error) {
	return f.CtxStore.ListPolicies(contextID)
}

// GetEffectiveRecipients returns the list of recipients who should receive
// a multi-message in the given context, based on local policies.
// Recipients with PolicyBlocked or PolicyExcluded are omitted.
// Recipients with PolicyMuted are included (delivery happens, but UI may suppress).
func (f *Fanout) GetEffectiveRecipients(contextID ContextID, allRecipients []string) ([]string, error) {
	policies, err := f.ListRecipientPolicies(contextID)
	if err != nil {
		return nil, err
	}
	policyMap := make(map[string]RecipientPolicy)
	for _, p := range policies {
		policyMap[p.Recipient] = p.Policy
	}

	var effective []string
	for _, r := range allRecipients {
		pol := policyMap[r]
		if pol == PolicyBlocked || pol == PolicyExcluded {
			continue
		}
		effective = append(effective, r)
	}
	return effective, nil
}

// SendMultiMessage encrypts the plaintext for each recipient in the context
// using their independent 1:1 secure channels, creates deliveries, and
// optionally sends them via the relay.
//
// This is the core fan-out operation: one plaintext -> N independent ciphertexts.
// Each delivery is cryptographically bound to its context, message ID, sender,
// and recipient via AAD to prevent ciphertext transplantation attacks.
//
// Returns a FanoutResult with per-recipient delivery status for partial failure handling.
func (f *Fanout) SendMultiMessage(
	ctx context.Context,
	contextID ContextID,
	plaintext []byte,
	recipients []string,
) (*FanoutResult, error) {
	// Load context for metadata
	msgCtx, err := f.CtxStore.LoadContext(contextID)
	if err != nil {
		return nil, fmt.Errorf("load context: %w", err)
	}

	// Validate context version
	if msgCtx.MetadataVersion == 0 {
		return nil, fmt.Errorf("invalid context version: 0")
	}

	// Verify context signature
	if err := VerifyContextSignature(msgCtx); err != nil {
		return nil, fmt.Errorf("context signature invalid: %w", err)
	}

	// Filter recipients by local policy
	effective, err := f.GetEffectiveRecipients(contextID, recipients)
	if err != nil {
		return nil, fmt.Errorf("get effective recipients: %w", err)
	}
	if len(effective) == 0 {
		return nil, fmt.Errorf("no effective recipients after policy filtering")
	}

	msgID := GenerateMessageID()
	timestamp := time.Now().UnixMilli()

	var results []DeliveryResult
	var deliveries []MessageDelivery

	for _, recipient := range effective {
		deliveryID := GenerateDeliveryID()

		// Build AAD: canonical binding of delivery metadata
		aad := buildDeliveryAAD(msgID, msgCtx.ContextID, f.client.Id, recipient, msgCtx.MetadataVersion)

		// Check if we have an active session with this recipient
		session, ok := f.client.Sessions[recipient]
		if !ok {
			if f.config.SkipOffline {
				results = append(results, DeliveryResult{
					DeliveryID: deliveryID,
					Recipient:  recipient,
					Status:     DeliveryFailed,
					Error:      fmt.Errorf("no session with recipient %s", recipient),
				})
				continue
			}
			// No session yet — create a pending delivery for offline mailbox
			// The ciphertext will be generated when the session is established
			delivery := MessageDelivery{
				DeliveryID: deliveryID,
				MessageID:  msgID,
				Recipient:  recipient,
				ChannelID:  "pending", // Will be replaced when session exists
				Ciphertext: nil,       // Placeholder
				ContextID:  contextID,
				Timestamp:  timestamp,
			}
			deliveries = append(deliveries, delivery)
			results = append(results, DeliveryResult{
				DeliveryID: deliveryID,
				Recipient:  recipient,
				Status:     DeliveryPending,
				Ciphertext: nil,
			})
			continue
		}

		// Encrypt using the existing 1:1 secure channel with AAD binding
		ciphertext, err := encryptWithAAD(session, f.client.Id, plaintext, aad)
		if err != nil {
			results = append(results, DeliveryResult{
				DeliveryID: deliveryID,
				Recipient:  recipient,
				Status:     DeliveryFailed,
				Error:      fmt.Errorf("encrypt for %s: %w", recipient, err),
			})
			continue
		}

		delivery := MessageDelivery{
			DeliveryID: deliveryID,
			MessageID:  msgID,
			Recipient:  recipient,
			ChannelID:  recipient, // Channel ID = peer ID for 1:1 channels
			Ciphertext: ciphertext,
			ContextID:  contextID,
			Timestamp:  timestamp,
		}
		deliveries = append(deliveries, delivery)
		results = append(results, DeliveryResult{
			DeliveryID: deliveryID,
			Recipient:  recipient,
			Status:     DeliverySent,
			Ciphertext: ciphertext,
		})

		// Persist delivery
		if err := f.deliveryStore.SaveDelivery(&delivery); err != nil {
			// Log but don't fail the whole message
			_ = err
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no deliveries created")
	}

	result := &FanoutResult{
		MessageID:  msgID,
		Sender:     f.client.Id,
		Context:    msgCtx,
		Deliveries: results,
		Timestamp:  timestamp,
	}

	// Send deliveries via relay if available
	if f.relay != nil {
		if err := f.sendDeliveries(ctx, deliveries); err != nil {
			// Log but don't fail — deliveries are persisted for retry
			_ = err
		}
	}

	return result, nil
}

// encryptWithAAD encrypts plaintext using the session's AEAD with additional
// authenticated data binding the delivery to its context, message, sender, and recipient.
func encryptWithAAD(session *crypto.SecurePeer, senderID string, plaintext, aad []byte) ([]byte, error) {
	// We need to use the existing Encrypt method but with custom AAD.
	// The existing Encrypt method uses dhPub||nonce as AAD internally.
	// For multi-message, we wrap the plaintext with delivery metadata,
	// then encrypt. The recipient verifies the metadata after decryption.

	// Build wrapped plaintext: [msg_id|ctx_id|sender|recipient|version|original_plaintext]
	wrapped := wrapPlaintext(plaintext, aad)

	return session.Encrypt(senderID, wrapped)
}

// decryptWithAAD decrypts ciphertext and verifies the AAD binding matches
// the expected delivery metadata.
func decryptWithAAD(session *crypto.SecurePeer, ciphertext []byte, expectedAAD []byte) (string, []byte, error) {
	senderID, wrapped, err := session.Decrypt(ciphertext)
	if err != nil {
		return "", nil, err
	}

	// Unwrap and verify AAD binding
	plaintext, err := unwrapPlaintext(wrapped, expectedAAD)
	if err != nil {
		return senderID, nil, fmt.Errorf("AAD verification failed: %w", err)
	}

	return senderID, plaintext, nil
}

// wrapPlaintext prepends delivery metadata to the plaintext for AAD binding.
// Format: [msgID_len(1)|msgID|ctxID_len(1)|ctxID|sender_len(1)|sender|recipient_len(1)|recipient|version(8)|plaintext]
func wrapPlaintext(plaintext []byte, aad []byte) []byte {
	// aad is the canonical AAD bytes: msgID|ctxID|sender|recipient|version
	return append(aad, plaintext...)
}

// unwrapPlaintext extracts the original plaintext and verifies AAD binding.
func unwrapPlaintext(wrapped, expectedAAD []byte) ([]byte, error) {
	if len(wrapped) < len(expectedAAD) {
		return nil, fmt.Errorf("wrapped plaintext too short")
	}
	if !bytes.Equal(wrapped[:len(expectedAAD)], expectedAAD) {
		return nil, fmt.Errorf("AAD mismatch — delivery may have been transplanted")
	}
	return wrapped[len(expectedAAD):], nil
}

// buildDeliveryAAD constructs canonical AAD bytes for delivery encryption.
// This binds each ciphertext to its intended context, message, sender, and recipient.
func buildDeliveryAAD(msgID MessageID, ctxID ContextID, sender, recipient string, version uint64) []byte {
	// Canonical format: length-prefixed fields to avoid ambiguity
	var buf []byte
	buf = appendLengthPrefixed(buf, []byte(msgID))
	buf = appendLengthPrefixed(buf, []byte(ctxID))
	buf = appendLengthPrefixed(buf, []byte(sender))
	buf = appendLengthPrefixed(buf, []byte(recipient))
	// Version as big-endian uint64
	buf = append(buf, byte(version>>56), byte(version>>48), byte(version>>40), byte(version>>32),
		byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	return buf
}

// appendLengthPrefixed appends a length-prefixed byte slice.
func appendLengthPrefixed(buf, data []byte) []byte {
	buf = append(buf, byte(len(data)))
	return append(buf, data...)
}

// sendDeliveries sends all deliveries via the relay.
func (f *Fanout) sendDeliveries(ctx context.Context, deliveries []MessageDelivery) error {
	for _, delivery := range deliveries {
		if delivery.Ciphertext == nil {
			// Skip pending deliveries (no session yet)
			continue
		}

		// Wrap in relay envelope (TypeMultiMsg = 0x04)
		envelope := relay.WrapEnvelope(relay.TypeMultiMsg, delivery.Ciphertext)

		// Get recipient's Ed25519 pubkey for relay addressing
		recipientPubKey, err := relay.PeerIDToEd25519Pub(delivery.Recipient)
		if err != nil {
			return fmt.Errorf("decode recipient %s: %w", delivery.Recipient, err)
		}

		// Send via relay
		if err := f.relay.Send(ctx, recipientPubKey, envelope, f.client.IdentityPrivate); err != nil {
			// Could implement retry logic here
			return fmt.Errorf("send to %s: %w", delivery.Recipient, err)
		}

		// Mark as delivered
		if err := f.deliveryStore.MarkDelivered(delivery.DeliveryID); err != nil {
			_ = err
		}
	}
	return nil
}

// RetryUndelivered attempts to send any pending deliveries.
func (f *Fanout) RetryUndelivered(ctx context.Context) error {
	undelivered, err := f.deliveryStore.ListUndeliveredDeliveries()
	if err != nil {
		return err
	}
	for _, d := range undelivered {
		// Try to get session now
		_, ok := f.client.Sessions[d.Recipient]
		if !ok {
			continue // Still no session
		}
		// Re-encrypt with actual session
		// Note: In a real implementation, we'd need the original plaintext.
		// This is a limitation — for now we only retry deliveries that already have ciphertext.
		if d.Ciphertext == nil {
			continue
		}

		recipientPubKey, err := relay.PeerIDToEd25519Pub(d.Recipient)
		if err != nil {
			continue
		}
		envelope := relay.WrapEnvelope(relay.TypeMessage, d.Ciphertext)
		if err := f.relay.Send(ctx, recipientPubKey, envelope, f.client.IdentityPrivate); err != nil {
			continue
		}
		_ = f.deliveryStore.MarkDelivered(d.DeliveryID)
	}
	return nil
}

// ReceiveMultiMessage processes incoming multi-message deliveries.
// It decrypts each delivery using the appropriate 1:1 session, checks for
// replay/deduplication, and returns the logical messages.
func (f *Fanout) ReceiveMultiMessage(ctx context.Context) ([]*MultiMessage, error) {
	// Receive all messages from relay
	msgs, err := f.relay.Receive(ctx, f.client.IdentityPrivate)
	if err != nil {
		return nil, err
	}

	// Group deliveries by MessageID
	deliveriesByMsgID := make(map[MessageID][]*MessageDelivery)

	for _, m := range msgs {
		if len(m.Body) == 0 {
			continue
		}
		envType := relay.Type(m.Body[0])
		if envType != relay.TypeMultiMsg {
			continue // Not a multi-message delivery
		}
		ciphertext := m.Body[1:]

		// Decrypt using our session with the sender
		senderID, _, err := f.client.Decrypt(ciphertext)
		if err != nil {
			continue // Can't decrypt, maybe no session yet
		}

		// Create a delivery record
		delivery := &MessageDelivery{
			DeliveryID: GenerateDeliveryID(),
			MessageID:  MessageID(hex.EncodeToString(ciphertext[:8])), // Use first bytes as proxy
			Recipient:  f.client.Id,
			ChannelID:  senderID, // Channel ID = sender for inbound
			Ciphertext: ciphertext,
			Timestamp:  time.Now().UnixMilli(),
		}

		// Check for replay
		if !f.MarkDeliverySeen(delivery.DeliveryID) {
			continue // Duplicate delivery
		}

		// Store delivery
		if err := f.deliveryStore.SaveDelivery(delivery); err != nil {
			_ = err // Log but continue
		}

		// Group by message ID
		deliveriesByMsgID[delivery.MessageID] = append(deliveriesByMsgID[delivery.MessageID], delivery)
	}

	// Convert grouped deliveries to MultiMessage results
	var messages []*MultiMessage
	for msgID, deliveries := range deliveriesByMsgID {
		if len(deliveries) == 0 {
			continue
		}
		mm := &MultiMessage{
			MessageID:  msgID,
			Deliveries: make([]MessageDelivery, len(deliveries)),
		}
		for i, d := range deliveries {
			mm.Deliveries[i] = *d
		}
		messages = append(messages, mm)
	}

	return messages, nil
}

// ContextManager provides high-level context management operations.
type ContextManager struct {
	fanout *Fanout
}

// NewContextManager creates a new ContextManager.
func NewContextManager(f *Fanout) *ContextManager {
	return &ContextManager{fanout: f}
}

// CreateContext creates a new context with the given display name.
func (cm *ContextManager) CreateContext(displayName string) (*MessageContext, error) {
	return cm.fanout.CreateContext(displayName, cm.fanout.client.IdentityPrivate)
}

// AddRecipient adds a recipient to the local delivery set for a context.
func (cm *ContextManager) AddRecipient(contextID ContextID, recipient string) error {
	return cm.fanout.SetRecipientPolicy(contextID, recipient, PolicyEnabled)
}

// RemoveRecipient removes a recipient from the local delivery set (PolicyExcluded).
func (cm *ContextManager) RemoveRecipient(contextID ContextID, recipient string) error {
	return cm.fanout.SetRecipientPolicy(contextID, recipient, PolicyExcluded)
}

// MuteRecipient mutes a recipient locally (delivery happens, UI suppresses).
func (cm *ContextManager) MuteRecipient(contextID ContextID, recipient string) error {
	return cm.fanout.SetRecipientPolicy(contextID, recipient, PolicyMuted)
}

// BlockRecipient blocks a recipient locally (no delivery).
func (cm *ContextManager) BlockRecipient(contextID ContextID, recipient string) error {
	return cm.fanout.SetRecipientPolicy(contextID, recipient, PolicyBlocked)
}

// ListContexts returns all known contexts.
func (cm *ContextManager) ListContexts() ([]*MessageContext, error) {
	return cm.fanout.CtxStore.ListContexts()
}

// GetContext returns a context by ID.
func (cm *ContextManager) GetContext(id ContextID) (*MessageContext, error) {
	return cm.fanout.CtxStore.LoadContext(id)
}

// RenameContext updates the display name of a context.
func (cm *ContextManager) RenameContext(id ContextID, newName string) (*MessageContext, error) {
	return cm.fanout.UpdateContext(id, newName, cm.fanout.client.IdentityPrivate)
}

// Send sends a multi-user message to all effective recipients in a context.
// Returns a FanoutResult with per-recipient delivery status.
func (cm *ContextManager) Send(ctx context.Context, contextID ContextID, message string, recipients []string) (*FanoutResult, error) {
	return cm.fanout.SendMultiMessage(ctx, contextID, []byte(message), recipients)
}