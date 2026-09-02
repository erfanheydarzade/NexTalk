// Package multimsg implements the multi-user message/fan-out layer for NexTalk.
package multimsg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// Fanout handles the creation and delivery of multi-user messages.
type Fanout struct {
	client        *client.Client
	relay         relay.Relay
	CtxStore      ContextStore
	deliveryStore DeliveryStore
	config        FanoutConfig
	mu            sync.Mutex
	// seenDeliveries tracks delivery IDs that have been processed to prevent replay.
	// This is an in-memory cache; persistent replay protection is handled by
	// the underlying crypto session's nonce tracking.
	seenDeliveries map[DeliveryID]bool
	// seenMessages dedupes inbound logical messages by (sender, MessageID),
	// so a group message is displayed once even if the relay redelivers the
	// envelope in the same session.
	seenMessages map[messageKey]bool
}

// messageKey identifies one logical inbound group message.
type messageKey struct {
	Sender    string
	MessageID MessageID
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
		client:         cl,
		relay:          r,
		CtxStore:       ctxStore,
		deliveryStore:  deliveryStore,
		config:         config,
		seenDeliveries: make(map[DeliveryID]bool),
		seenMessages:   make(map[messageKey]bool),
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
	stored, err := f.CtxStore.LoadContext(contextID)
	if err != nil {
		return nil, fmt.Errorf("load context: %w", err)
	}
	if stored.CreatorID != f.client.Id {
		return nil, fmt.Errorf("only context creator can update metadata")
	}

	// Enforce monotonic version increase
	newVersion := stored.MetadataVersion + 1
	if newVersion <= stored.MetadataVersion {
		return nil, fmt.Errorf("context version overflow")
	}

	// Build a fresh struct rather than mutating the stored one in place:
	// stores may hand back their internal pointer, and SaveContext's
	// monotonicity check compares against the stored version — mutating it
	// first would make the update compare against itself and be rejected.
	ctx := &MessageContext{
		ContextID:       stored.ContextID,
		DisplayName:     newDisplayName,
		MetadataVersion: newVersion,
		CreatorID:       stored.CreatorID,
	}
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
		ciphertext, err := encryptWithAAD(session, f.client.Id, plaintext, aad, msgCtx)
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

	// Persist the advanced ratchet state. Encryption above goes through
	// session.Encrypt directly (not Client.Encrypt), so without an explicit
	// save the send-chain nonces advance in memory only. A subsequent
	// process would re-send with already-consumed nonces and every receiver
	// would hard-reject the delivery as a replay.
	for _, r := range results {
		if r.Status == DeliverySent {
			client.SaveClient(f.client)
			break
		}
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
// authenticated data binding the delivery to its context, message, sender, and
// recipient. The wrapped payload (v2 wire format) embeds the same binding
// inside the ciphertext plus the creator-signed context descriptor, so the
// recipient can parse which group/message a delivery belongs to and verify it
// was not transplanted.
func encryptWithAAD(session *crypto.SecurePeer, senderID string, plaintext, aad []byte, msgCtx *MessageContext) ([]byte, error) {
	wrapped, err := wrapPayloadV2(aad, msgCtx, plaintext)
	if err != nil {
		return nil, err
	}
	return session.Encrypt(senderID, wrapped)
}

// wrapPlaintext / unwrapPlaintext define the legacy v1 wire shape
// (AAD || plaintext) and are kept as the reference implementation used by
// the compatibility tests; current sends go through wrapPayloadV2.
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

// InboundMessage is one decrypted, verified group message.
type InboundMessage struct {
	// Sender is the authenticated author (HMAC-verified by the ratchet).
	Sender string
	// Meta is the binding parsed from inside the ciphertext.
	Meta DeliveryMeta
	// Context is the resolved context descriptor, preferring the sender's
	// embedded metadata and falling back to any locally stored copy.
	Context *MessageContext
	// Plaintext is the original message body.
	Plaintext []byte
}

// ContextID returns the group this message belongs to.
func (m *InboundMessage) ContextID() ContextID {
	if m.Context != nil && m.Context.ContextID != "" {
		return m.Context.ContextID
	}
	return m.Meta.ContextID
}

// DisplayName returns a human-readable group name, falling back to a
// truncated context ID for unknown groups.
func (m *InboundMessage) DisplayName() string {
	if m.Context != nil && m.Context.DisplayName != "" {
		return m.Context.DisplayName
	}
	id := string(m.Meta.ContextID)
	if len(id) > 8 {
		id = id[:8]
	}
	return "group:" + id
}

// ProcessDelivery decrypts one inbound TypeMultiMsg ciphertext against the
// local session with the sender, parses the wrapped payload, verifies the
// delivery binding (rejecting transplanted ciphertexts), applies any embedded
// context metadata to the local store, dedupes redeliveries, and returns the
// logical message.
func (f *Fanout) ProcessDelivery(selfID string, ciphertext []byte) (*InboundMessage, error) {
	frameSender, wrapped, err := f.client.Decrypt(ciphertext)
	if err != nil {
		if errors.Is(err, crypto.ErrReplay) {
			// Wrap (%w) rather than replace, so callers upstream can still
			// classify the failure via errors.Is.
			return nil, fmt.Errorf(
				"message from %s rejected: the sender's session state was rolled back "+
					"(two NexTalk processes sharing their identity?) — have them run 'connect' again: %w",
				shortPeer(frameSender), err)
		}
		return nil, fmt.Errorf("decrypt delivery: %w", err)
	}

	parsed, err := ParseWrapped(wrapped)
	if err != nil {
		return nil, fmt.Errorf("parse delivery from %s: %w", shortPeer(frameSender), err)
	}

	// Binding checks: the AAD claims are authenticated only insofar as they
	// agree with the ratchet-authenticated sender and our own identity.
	if parsed.Meta.Sender != "" && parsed.Meta.Sender != frameSender {
		return nil, fmt.Errorf("delivery binding mismatch: claimed sender %s but frame sender %s",
			shortPeer(parsed.Meta.Sender), shortPeer(frameSender))
	}
	if parsed.Meta.Recipient != "" && parsed.Meta.Recipient != selfID {
		return nil, fmt.Errorf("delivery bound to another recipient (%s) — transplant rejected",
			shortPeer(parsed.Meta.Recipient))
	}
	if parsed.Meta.Sender == "" {
		parsed.Meta.Sender = frameSender
	}

	// Dedupe on (sender, message ID). The Double Ratchet already rejects
	// replayed identical frames; this catches distinct re-encryptions of the
	// same logical message within one process lifetime.
	key := messageKey{Sender: frameSender, MessageID: parsed.Meta.MessageID}
	f.mu.Lock()
	seen := f.seenMessages[key]
	if !seen {
		f.seenMessages[key] = true
	}
	f.mu.Unlock()
	if seen {
		return nil, ErrDuplicateDelivery
	}

	// Learn/refresh group metadata from the signed descriptor when present.
	if parsed.Context != nil {
		if err := f.ApplyRemoteContext(parsed.Context); err != nil {
			// Stale-version conflicts mean we already know newer metadata —
			// keep going with what we have rather than dropping the message.
			parsed.Context = nil
		}
	}
	if parsed.Context == nil {
		// Fall back to locally stored metadata (e.g. we are also a member).
		if ctx, err := f.CtxStore.LoadContext(parsed.Meta.ContextID); err == nil {
			parsed.Context = ctx
		}
	}

	return &InboundMessage{
		Sender:    frameSender,
		Meta:      parsed.Meta,
		Context:   parsed.Context,
		Plaintext: parsed.Plaintext,
	}, nil
}

// ReceiveMultiMessage polls the relay and processes every inbound
// multi-message delivery. Envelopes that fail to decrypt or verify are
// skipped so one bad peer cannot block the batch.
func (f *Fanout) ReceiveMultiMessage(ctx context.Context) ([]*InboundMessage, error) {
	msgs, err := f.relay.Receive(ctx, f.client.IdentityPrivate)
	if err != nil {
		return nil, err
	}

	var messages []*InboundMessage
	for _, m := range msgs {
		if len(m.Body) == 0 || relay.Type(m.Body[0]) != relay.TypeMultiMsg {
			continue // Not a multi-message delivery
		}
		inbound, err := f.ProcessDelivery(f.client.Id, m.Body[1:])
		if err != nil {
			continue // Undecryptable, duplicate, or untrusted — skip
		}
		messages = append(messages, inbound)
	}
	return messages, nil
}
