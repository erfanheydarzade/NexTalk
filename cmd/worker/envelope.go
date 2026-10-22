package worker

import (
	"context"
	"crypto/ed25519"

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

// ed25519PubFromID extracts the Ed25519 public key (first 32 bytes) from a
// base58-encoded peer ID: base58(Ed25519[32] + sha3_256(Dilithium)[32]).
//
// Thin wrapper kept for call-site stability inside this package — the real
// implementation is relay.PeerIDToEd25519Pub, shared with every other Relay
// caller (including the wasm bridge; see internal/wasmbridge/relay.go).
func ed25519PubFromID(peerID string) ([]byte, error) {
	return relay.PeerIDToEd25519Pub(peerID)
}

// sendEnvelope wraps data in a type-tagged envelope and delivers it to
// recipientPubKey. Sender-auth signing happens inside r.Send itself — this
// only frames the payload.
//
// Thin wrapper kept for call-site stability inside this package — the real
// implementation is relay.SendEnvelope, shared with every other Relay
// caller (including the wasm bridge; see internal/wasmbridge/relay.go).
func sendEnvelope(
	ctx context.Context,
	r relay.Relay,
	senderPriv ed25519.PrivateKey,
	recipientPubKey []byte,
	t relay.Type,
	data []byte,
) error {
	return relay.SendEnvelope(ctx, r, senderPriv, recipientPubKey, t, data)
}
