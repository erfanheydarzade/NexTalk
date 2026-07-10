package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	base58 "github.com/mr-tron/base58"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

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
	data json.RawMessage,
) error {
	env := relay.Envelope{Type: t, Data: data}
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return r.Send(ctx, recipientPubKey, payload, senderPriv)
}

func tryDecode(b []byte) []byte {
	d, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return b
	}
	return d
}
