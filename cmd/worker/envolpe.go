package worker

import (
	"context"
	"crypto/ed25519"
	"fmt"

	base58 "github.com/mr-tron/base58"

	codec "github.com/erfanheydarzade/NexTalk/internal/codec"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// readInput is a back-compat wrapper for interactive callers (the REPL in
// worker.go and the GUI transport in register.go) that only ever supply an
// inline message with no file/encoding flags of their own. Cobra-based
// commands should call readPayload directly so they can expose -f/--in.
func readInput(message string) ([]byte, error) {
	return readPayload(message, "", string(codec.EncodingRaw))
}

// peerIDByteLen is the expected decoded length of a base58 peer ID:
// Ed25519 public key (32 bytes) + SHA3-256(Dilithium public key) (32 bytes).
const peerIDByteLen = 64

// ed25519PubFromID extracts the Ed25519 public key (first 32 bytes) from a
// base58-encoded peer ID: base58(Ed25519[32] + sha3_256(Dilithium)[32]).
func ed25519PubFromID(peerID string) ([]byte, error) {
	raw, err := base58.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("base58 decode: %w", err)
	}
	if len(raw) != peerIDByteLen {
		return nil, fmt.Errorf("invalid peer ID: decoded length %d, want %d", len(raw), peerIDByteLen)
	}
	return raw[:32], nil
}

// sendEnvelope wraps data in a relay.Envelope of the given type and delivers
// it to recipientPubKey. Sender-auth signing happens inside r.Send itself —
// this function only marshals the envelope and passes the identity key through.
func sendEnvelope(
	ctx context.Context,
	r relay.Relay,
	senderPriv ed25519.PrivateKey,
	recipientPubKey []byte,
	t relay.Type,
	data []byte,
) error {
	payload := make([]byte, 1+len(data))
	payload[0] = byte(t)
	copy(payload[1:], data)

	return r.Send(ctx, recipientPubKey, payload, senderPriv)
}
