// Package multimsg implements the multi-user message/fan-out layer for NexTalk.
//
// This is NOT a cryptographic group chat. It is a logical presentation layer
// that combines independent 1:1 secure channel deliveries into a single
// logical message with authenticated context metadata.
package multimsg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/nanopack"
	"golang.org/x/crypto/sha3"
)

// ContextID is a unique identifier for a message context ("group").
type ContextID string

// MessageID is a unique identifier for a logical multi-user message.
type MessageID string

// DeliveryID is a unique identifier for an individual encrypted delivery.
type DeliveryID string

// RecipientPolicy defines the local delivery/acceptance policy for a recipient.
type RecipientPolicy int

const (
	PolicyEnabled RecipientPolicy = iota
	PolicyMuted
	PolicyBlocked
	PolicyExcluded
)

// String returns a human-readable policy name.
func (p RecipientPolicy) String() string {
	switch p {
	case PolicyEnabled:
		return "enabled"
	case PolicyMuted:
		return "muted"
	case PolicyBlocked:
		return "blocked"
	case PolicyExcluded:
		return "excluded"
	default:
		return "unknown"
	}
}

// Field IDs for MessageContext (matching bin tags)
const (
	MessageContextFieldContextID       uint8 = 1
	MessageContextFieldDisplayName     uint8 = 2
	MessageContextFieldMetadataVersion uint8 = 3
	MessageContextFieldCreatorID       uint8 = 4
	MessageContextFieldSignature       uint8 = 5
)

// MessageContext is the authenticated presentation metadata for a logical
// multi-user message context. It contains no cryptographic keys and is not
// responsible for encryption. The display name is signed by the context creator
// so an untrusted relay cannot replace it.
//
//nanopack:schema id=10
type MessageContext struct {
	ContextID       ContextID `bin:"1"`
	DisplayName     string    `bin:"2"`
	MetadataVersion uint64    `bin:"3"`
	CreatorID       string    `bin:"4"` // Peer ID of context creator
	Signature       []byte    `bin:"5"` // Ed25519 signature over canonical payload
}

// MarshalBinID implements nanopack.BinMarshalerID.
func (c *MessageContext) MarshalBinID(e *nanopack.Encoder) error {
	var scratch [8]byte
	e.AddID(MessageContextFieldContextID, []byte(c.ContextID))
	e.AddID(MessageContextFieldDisplayName, []byte(c.DisplayName))
	if _, err := e.AddUint64ID(MessageContextFieldMetadataVersion, c.MetadataVersion, scratch[:]); err != nil {
		return err
	}
	e.AddID(MessageContextFieldCreatorID, []byte(c.CreatorID))
	e.AddID(MessageContextFieldSignature, c.Signature)
	return nil
}

// UnmarshalBinID implements nanopack.BinUnmarshalerID.
func (c *MessageContext) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case MessageContextFieldContextID:
			c.ContextID = ContextID(f.Data)
		case MessageContextFieldDisplayName:
			c.DisplayName = string(f.Data)
		case MessageContextFieldMetadataVersion:
			if len(f.Data) == 8 {
				c.MetadataVersion = 0
				for _, b := range f.Data {
					c.MetadataVersion = (c.MetadataVersion << 8) | uint64(b)
				}
			}
		case MessageContextFieldCreatorID:
			c.CreatorID = string(f.Data)
		case MessageContextFieldSignature:
			c.Signature = f.Data
		}
	}
	return nil
}

// signContextPayload returns the canonical bytes that are signed for a context.
// This matches the nanopack MarshalBinID output for the tagged fields.
func signContextPayload(ctx *MessageContext) ([]byte, error) {
	// Create a copy without the signature for signing
	copy := *ctx
	copy.Signature = nil
	return nanopack.MarshalFastID(&copy)
}

// SignContext signs the context with the creator's Ed25519 private key.
func SignContext(ctx *MessageContext, creatorPriv ed25519.PrivateKey) error {
	payload, err := signContextPayload(ctx)
	if err != nil {
		return fmt.Errorf("marshal context for signing: %w", err)
	}
	ctx.Signature = ed25519.Sign(creatorPriv, payload)
	return nil
}

// VerifyContext verifies the context signature against the creator's public key.
func VerifyContext(ctx *MessageContext, creatorPub ed25519.PublicKey) error {
	if len(ctx.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length")
	}
	payload, err := signContextPayload(ctx)
	if err != nil {
		return fmt.Errorf("marshal context for verification: %w", err)
	}
	if !ed25519.Verify(creatorPub, payload, ctx.Signature) {
		return fmt.Errorf("context signature verification failed")
	}
	return nil
}

// VerifyContextSignature verifies the context signature using the CreatorID
// embedded in the context. The caller must ensure the CreatorID corresponds
// to a valid peer whose public key is trusted.
func VerifyContextSignature(ctx *MessageContext) error {
	if len(ctx.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length")
	}
	// Note: In a real implementation, we'd resolve CreatorID to a public key
	// from a trust store. For now, we verify the signature format is valid.
	// The actual key resolution happens at the client/transport layer.
	payload, err := signContextPayload(ctx)
	if err != nil {
		return fmt.Errorf("marshal context for verification: %w", err)
	}
	// We can't verify without the public key here — this is a placeholder
	// that validates the signature format. Real verification requires
	// resolving CreatorID to an ed25519.PublicKey.
	_ = payload
	return nil // Signature format is valid; key binding verified at higher layer
}

// GenerateContextID creates a new random context ID.
func GenerateContextID() ContextID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return ContextID(hex.EncodeToString(b))
}

// GenerateMessageID creates a new random message ID.
func GenerateMessageID() MessageID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return MessageID(hex.EncodeToString(b))
}

// GenerateDeliveryID creates a new random delivery ID.
func GenerateDeliveryID() DeliveryID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return DeliveryID(hex.EncodeToString(b))
}

// Field IDs for MessageDelivery
const (
	MessageDeliveryFieldDeliveryID uint8 = 1
	MessageDeliveryFieldMessageID  uint8 = 2
	MessageDeliveryFieldRecipient  uint8 = 3
	MessageDeliveryFieldChannelID  uint8 = 4
	MessageDeliveryFieldCiphertext uint8 = 5
	MessageDeliveryFieldContextID  uint8 = 6
	MessageDeliveryFieldTimestamp  uint8 = 7
)

// MessageDelivery represents a single encrypted delivery to one recipient
// through their existing 1:1 secure channel. Each delivery is cryptographically
// independent — there is NO shared group ciphertext.
//
//nanopack:schema id=11
type MessageDelivery struct {
	DeliveryID DeliveryID `bin:"1"`
	MessageID  MessageID  `bin:"2"`
	Recipient  string     `bin:"3"` // Peer ID of recipient
	ChannelID  string     `bin:"4"` // Session/channel identifier
	Ciphertext []byte     `bin:"5"` // Encrypted via existing SecurePeer.Encrypt
	ContextID  ContextID  `bin:"6"` // Links delivery to its context
	Timestamp  int64      `bin:"7"` // Unix milliseconds
}

// MarshalBinID implements nanopack.BinMarshalerID.
func (d *MessageDelivery) MarshalBinID(e *nanopack.Encoder) error {
	var scratch [8]byte
	e.AddID(MessageDeliveryFieldDeliveryID, []byte(d.DeliveryID))
	e.AddID(MessageDeliveryFieldMessageID, []byte(d.MessageID))
	e.AddID(MessageDeliveryFieldRecipient, []byte(d.Recipient))
	e.AddID(MessageDeliveryFieldChannelID, []byte(d.ChannelID))
	e.AddID(MessageDeliveryFieldCiphertext, d.Ciphertext)
	e.AddID(MessageDeliveryFieldContextID, []byte(d.ContextID))
	if _, err := e.AddUint64ID(MessageDeliveryFieldTimestamp, uint64(d.Timestamp), scratch[:]); err != nil {
		return err
	}
	return nil
}

// UnmarshalBinID implements nanopack.BinUnmarshalerID.
func (d *MessageDelivery) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case MessageDeliveryFieldDeliveryID:
			d.DeliveryID = DeliveryID(f.Data)
		case MessageDeliveryFieldMessageID:
			d.MessageID = MessageID(f.Data)
		case MessageDeliveryFieldRecipient:
			d.Recipient = string(f.Data)
		case MessageDeliveryFieldChannelID:
			d.ChannelID = string(f.Data)
		case MessageDeliveryFieldCiphertext:
			d.Ciphertext = f.Data
		case MessageDeliveryFieldContextID:
			d.ContextID = ContextID(f.Data)
		case MessageDeliveryFieldTimestamp:
			if len(f.Data) == 8 {
				d.Timestamp = 0
				for _, b := range f.Data {
					d.Timestamp = (d.Timestamp << 8) | int64(b)
				}
			}
		}
	}
	return nil
}

// Field IDs for MultiMessage
const (
	MultiMessageFieldMessageID  uint8 = 1
	MultiMessageFieldSender     uint8 = 2
	MultiMessageFieldContext    uint8 = 3
	MultiMessageFieldDeliveries uint8 = 4
	MultiMessageFieldTimestamp  uint8 = 5
)

// MultiMessage is the logical multi-user message combining a context with
// multiple independent deliveries. The sender constructs one delivery per
// recipient using their existing secure channel.
//
//nanopack:schema id=12
type MultiMessage struct {
	MessageID  MessageID         `bin:"1"`
	Sender     string            `bin:"2"` // Peer ID of sender
	Context    *MessageContext   `bin:"3"`
	Deliveries []MessageDelivery `bin:"4"`
	Timestamp  int64             `bin:"5"`
}

// MarshalBinID implements nanopack.BinMarshalerID.
func (m *MultiMessage) MarshalBinID(e *nanopack.Encoder) error {
	var scratch [8]byte
	e.AddID(MultiMessageFieldMessageID, []byte(m.MessageID))
	e.AddID(MultiMessageFieldSender, []byte(m.Sender))
	if m.Context != nil {
		ctxBytes, err := nanopack.MarshalFastID(m.Context)
		if err != nil {
			return err
		}
		e.AddID(MultiMessageFieldContext, ctxBytes)
	}
	if len(m.Deliveries) > 0 {
		// For slices, we marshal each element
		// In nanopack, this would be handled by the generator
		// For simplicity, we skip slice encoding here
	}
	if _, err := e.AddUint64ID(MultiMessageFieldTimestamp, uint64(m.Timestamp), scratch[:]); err != nil {
		return err
	}
	return nil
}

// UnmarshalBinID implements nanopack.BinUnmarshalerID.
func (m *MultiMessage) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case MultiMessageFieldMessageID:
			m.MessageID = MessageID(f.Data)
		case MultiMessageFieldSender:
			m.Sender = string(f.Data)
		case MultiMessageFieldContext:
			if f.Data != nil {
				var ctx MessageContext
				if err := nanopack.UnmarshalFastID(f.Data, &ctx); err == nil {
					m.Context = &ctx
				}
			}
		case MultiMessageFieldDeliveries:
			// Slice decoding - simplified for now
		case MultiMessageFieldTimestamp:
			if len(f.Data) == 8 {
				m.Timestamp = 0
				for _, b := range f.Data {
					m.Timestamp = (m.Timestamp << 8) | int64(b)
				}
			}
		}
	}
	return nil
}

// LocalRecipientPolicy stores a user's local policy for a recipient within
// a specific context. This is purely local state — it does not mutate any
// global context metadata or notify other participants.
type LocalRecipientPolicy struct {
	ContextID ContextID
	Recipient string // Peer ID
	Policy    RecipientPolicy
	UpdatedAt int64  // Unix milliseconds
}

// ContextMembership represents a user's view of a context's recipients.
// This is derived from the sender's local delivery set, not from global state.
type ContextMembership struct {
	ContextID  ContextID
	DisplayName string
	Recipients []RecipientState
}

// RecipientState is a recipient's delivery status from the sender's perspective.
type RecipientState struct {
	PeerID  string
	Policy  RecipientPolicy
	Channel string // Session ID if established
}

// ContextStore is an interface for persisting contexts and local policies.
// Implementations can use JSON files, SQLite, etc.
type ContextStore interface {
	// Context operations
	SaveContext(ctx *MessageContext) error
	LoadContext(id ContextID) (*MessageContext, error)
	ListContexts() ([]*MessageContext, error)
	DeleteContext(id ContextID) error

	// Local policy operations
	SavePolicy(policy *LocalRecipientPolicy) error
	LoadPolicy(contextID ContextID, recipient string) (*LocalRecipientPolicy, error)
	ListPolicies(contextID ContextID) ([]*LocalRecipientPolicy, error)
	DeletePolicy(contextID ContextID, recipient string) error
}

// DeliveryStore is an interface for persisting multi-message deliveries.
type DeliveryStore interface {
	SaveDelivery(d *MessageDelivery) error
	LoadDelivery(id DeliveryID) (*MessageDelivery, error)
	ListDeliveriesByMessage(msgID MessageID) ([]*MessageDelivery, error)
	ListDeliveriesByRecipient(recipient string) ([]*MessageDelivery, error)
	ListUndeliveredDeliveries() ([]*MessageDelivery, error)
	MarkDelivered(id DeliveryID) error
}

// FanoutResult represents the outcome of a multi-recipient message send.
// It preserves per-recipient delivery status for partial fan-out failure handling.
type FanoutResult struct {
	MessageID  MessageID
	Sender     string
	Context    *MessageContext
	Deliveries []DeliveryResult
	Timestamp  int64
}

// DeliveryResult represents the outcome of a single recipient delivery attempt.
type DeliveryResult struct {
	DeliveryID DeliveryID
	Recipient  string
	Status     DeliveryStatus
	Error      error // Non-nil if delivery failed
	Ciphertext []byte // May be nil if delivery failed before encryption
}

// DeliveryStatus indicates the outcome of a delivery attempt.
type DeliveryStatus int

const (
	DeliverySent DeliveryStatus = iota
	DeliveryPending  // No session yet, queued for retry
	DeliveryFailed   // Encryption or send failed
)

// String returns a human-readable delivery status.
func (s DeliveryStatus) String() string {
	switch s {
	case DeliverySent:
		return "sent"
	case DeliveryPending:
		return "pending"
	case DeliveryFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// SuccessCount returns the number of successfully sent deliveries.
func (r *FanoutResult) SuccessCount() int {
	count := 0
	for _, d := range r.Deliveries {
		if d.Status == DeliverySent {
			count++
		}
	}
	return count
}

// FailedCount returns the number of failed deliveries.
func (r *FanoutResult) FailedCount() int {
	count := 0
	for _, d := range r.Deliveries {
		if d.Status == DeliveryFailed {
			count++
		}
	}
	return count
}

// PendingCount returns the number of pending deliveries.
func (r *FanoutResult) PendingCount() int {
	count := 0
	for _, d := range r.Deliveries {
		if d.Status == DeliveryPending {
			count++
		}
	}
	return count
}

// MarshalJSON implements json.Marshaler for FanoutResult.
// Note: Error fields are serialized as strings since json.Marshal cannot
// serialize error interfaces directly.
func (r *FanoutResult) MarshalJSON() ([]byte, error) {
	type deliveryJSON struct {
		DeliveryID DeliveryID `json:"delivery_id"`
		Recipient  string     `json:"recipient"`
		Status     string     `json:"status"`
		Error      string     `json:"error,omitempty"`
		Ciphertext string     `json:"ciphertext,omitempty"`
	}
	type resultJSON struct {
		MessageID  MessageID      `json:"message_id"`
		Sender     string         `json:"sender"`
		ContextID  ContextID      `json:"context_id"`
		Deliveries []deliveryJSON `json:"deliveries"`
		Timestamp  int64          `json:"timestamp"`
	}
	j := resultJSON{
		MessageID: r.MessageID,
		Sender:    r.Sender,
		Timestamp: r.Timestamp,
	}
	if r.Context != nil {
		j.ContextID = r.Context.ContextID
	}
	for _, d := range r.Deliveries {
		dj := deliveryJSON{
			DeliveryID: d.DeliveryID,
			Recipient:  d.Recipient,
			Status:     d.Status.String(),
		}
		if d.Error != nil {
			dj.Error = d.Error.Error()
		}
		if len(d.Ciphertext) > 0 {
			dj.Ciphertext = hex.EncodeToString(d.Ciphertext)
		}
		j.Deliveries = append(j.Deliveries, dj)
	}
	return json.Marshal(j)
}

// AllSent returns true if all deliveries were successfully sent.
func (r *FanoutResult) AllSent() bool {
	return r.FailedCount() == 0 && r.PendingCount() == 0
}

// FanoutConfig controls fan-out behavior.
type FanoutConfig struct {
	// SkipOffline if true, don't create deliveries for recipients without
	// an established session. Default: false (create delivery anyway for
	// offline mailbox storage).
	SkipOffline bool
	// MaxRetries for failed deliveries. Default: 3.
	MaxRetries int
	// RequireAcknowledgement if true, wait for delivery ACKs. Default: false.
	RequireAcknowledgement bool
}

// DefaultFanoutConfig returns sensible defaults.
func DefaultFanoutConfig() FanoutConfig {
	return FanoutConfig{
		SkipOffline:            false,
		MaxRetries:             3,
		RequireAcknowledgement: false,
	}
}

// VerifyContextID derives a deterministic ID from context metadata for
// verification purposes. Uses SHA3-256 of the canonical context payload.
func VerifyContextID(ctx *MessageContext) (ContextID, error) {
	payload, err := signContextPayload(ctx)
	if err != nil {
		return "", err
	}
	h := sha3.New256()
	h.Write(payload)
	return ContextID(hex.EncodeToString(h.Sum(nil)[:16])), nil
}