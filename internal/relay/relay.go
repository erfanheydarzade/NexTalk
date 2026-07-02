// internal/relay/relay.go
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Message Relay is the single interface every transport backend must satisfy.
// It deliberately knows nothing about handshake logic or encryption —
// those live in core.Engine. Relay only moves opaque bytes.
type Message struct {
	Body []byte
}

// SenderAuth proves the caller of Send controls the private key for
// SenderAuth.PubKey. As of the mailbox worker's sender-authentication
// update, every Send must carry one of these — the worker signature-checks
// it before accepting a message, binding sender identity, recipient, and
// the exact message content together so a captured auth can't be replayed
// against a different recipient or with swapped message bytes.
//
// Build one with BuildSenderAuth rather than constructing it by hand —
// every caller (CLI commands, the GUI, anything else) MUST sign the exact
// same message format below, or the worker will reject it as an invalid
// signature. Centralizing this in one function is what guarantees that.
type SenderAuth struct {
	PubKey    string `json:"pubkey"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

// BuildSenderAuth signs the message the mailbox worker's /send handler
// verifies:
//
//	send:{senderPubkeyLowerHex}:{recipientPubkeyLowerHex}:{timestamp}:{sha256hex(payload)}
//
// senderPriv must be the full 64-byte ed25519.PrivateKey (seed + public
// key), i.e. Client.IdentityPrivate — not just the 32-byte seed.
// recipientPubKey is the raw 32-byte Ed25519 public key of the recipient.
//
// This is the ONE place this signing scheme is implemented. Every caller
// (cmd/worker.go's CLI commands, shell.go's WorkerTransport, anything future)
// should call this instead of reimplementing the signed-message format —
// that reimplementation is exactly how the CLI and GUI drifted out of sync
// before (the GUI's transport.Client.Send never got sender auth added at
// all, while the CLI's Adapter.Send did).
func BuildSenderAuth(senderPriv ed25519.PrivateKey, recipientPubKey []byte, payload []byte) (SenderAuth, error) {
	pub, ok := senderPriv.Public().(ed25519.PublicKey)
	if !ok {
		return SenderAuth{}, fmt.Errorf("relay: invalid ed25519 private key")
	}
	senderHex := hex.EncodeToString(pub)
	recipientHex := hex.EncodeToString(recipientPubKey)
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	msgHash := sha256.Sum256(payload)
	msgHashHex := hex.EncodeToString(msgHash[:])

	signedMessage := fmt.Sprintf("send:%s:%s:%s:%s", senderHex, recipientHex, timestamp, msgHashHex)
	sig := ed25519.Sign(senderPriv, []byte(signedMessage))

	return SenderAuth{
		PubKey:    senderHex,
		Timestamp: timestamp,
		Signature: hex.EncodeToString(sig),
	}, nil
}

type Relay interface {
	Register(ctx context.Context, privateKey []byte) (string, error)
	// Send signs and transmits payload to recipientPubKey. senderPriv is the
	// caller's own identity private key — the implementation is responsible
	// for building SenderAuth (via BuildSenderAuth) over whatever bytes it
	// actually places in the wire request, AFTER any transport-level
	// encoding (e.g. base64). This is deliberate: if the caller built
	// SenderAuth itself before handing payload to Send, it would sign the
	// pre-encoding bytes while the worker hashes the post-encoding string
	// it actually received, and every signature would fail verification —
	// that exact bug is why this method takes a raw key, not a pre-built
	// SenderAuth.
	Send(ctx context.Context, recipientPubKey []byte, payload []byte, senderPriv ed25519.PrivateKey) error
	Receive(ctx context.Context, privateKey []byte) ([]Message, error)
}

// ---- Envelope ---------------------------------------------------------------

// Type is the discriminator for the three payload kinds in the protocol.
type Type string

const (
	TypeOffer   Type = "offer"
	TypeAnswer  Type = "answer"
	TypeMessage Type = "message"
)

// Envelope is the common wire wrapper used by all relay implementations.
// The proxy backend previously used named buckets ("offers", "answers",
// "messages") for the same purpose; with this type both backends unify.
type Envelope struct {
	Type Type            `json:"type"`
	Data json.RawMessage `json:"data"`
}
