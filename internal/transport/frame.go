package transport

import (
	"context"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// Frame is one opaque core frame: [type byte][nanopack payload]
// (internal/frame vocabulary). Transports never inspect it.
type Frame = []byte

// RouteHint tells a transport where a frame goes. Transports resolve it
// according to their own addressing:
//
//	relay-example  recipient_pub → mailbox = sha256(pub)[:16] (no registration)
//	filerelay      mailbox_id + shard_url shared by the recipient out-of-band
//	               (scoped-credential mailboxes are unguessable by design);
//	               recipient_pub alone only resolves deterministically-mapped
//	               mailboxes and otherwise yields an unregistered guess.
//
// senderHint is a 0/32B public key for logging only — never key material.
type RouteHint struct {
	RecipientPub []byte
	SenderHint   []byte
	MailboxID    []byte // 0/16B explicit recipient mailbox
	ShardURL     string // explicit shard for MailboxID
}

// FrameTransport is the runtime interface every transport — built-in shim
// or external process — satisfies. It deals strictly in opaque frames and
// routing hints. There is deliberately no private-key parameter anywhere.
//
// This is intentionally narrower than relay.Relay (whose Register/Send
// take private keys by design for the in-process worker adapter). External
// transports must not implement relay.Relay; built-in shims keep working
// while dispatch migrates to polled frames.
type FrameTransport interface {
	// ID returns the manifest id (e.g. "filerelay").
	ID() string
	// Capabilities lists manifest capabilities (e.g. ["message"]).
	Capabilities() []string
	// Start/Stop manage the transport lifecycle.
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	// SendFrame delivers one opaque frame per the route hint.
	SendFrame(ctx context.Context, frame Frame, to RouteHint) error
	// AttachMailbox subscribes a mailbox for polling (bearer: read_secret).
	AttachMailbox(ctx context.Context, mailboxID, readSecret []byte, shardURL, routerURL string) error
	// DetachMailbox unsubscribes a mailbox.
	DetachMailbox(ctx context.Context, mailboxID []byte) error
	// PollFrames returns up to limit full frames ([type][payload] each).
	PollFrames(ctx context.Context, limit int, mailboxID []byte) ([][]byte, error)
	// Status reports liveness.
	Status(ctx context.Context) (running bool, detail string, err error)
}

// SupportsCapability reports whether t declares cap.
func SupportsCapability(t FrameTransport, cap string) bool {
	for _, c := range t.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// WrapFrame builds a full frame from type + payload (single definition of
// the layer-1 layout for transport callers).
func WrapFrame(t relay.Type, payload []byte) Frame {
	out := make([]byte, 1+len(payload))
	out[0] = byte(t)
	copy(out[1:], payload)
	return out
}
