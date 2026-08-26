// Package frame is THE standard payload framing for every NexTalk transport.
//
// Two layers, used by all of worker / offline / proxy / wasm alike:
//
// Layer 1 — the canonical wire frame:
//
//	[type byte][nanopack payload bytes]
//
// One byte says what the payload is (the Type registry below); the payload is
// always a nanopack body. This is what Relay.Send carries and what
// UnwrapEnvelope hands to dispatch code. There is exactly ONE definition of
// it — this package — so transports can never drift.
//
// Layer 2 — the transfer container:
//
//	{ "Type": "offer", "Data": "<base64 of the FULL frame>" }
//
// A small JSON object used wherever a human moves bytes (copy/paste across an
// air gap, QR codes, files). Data carries base64 of the complete layer-1
// frame INCLUDING its type byte, so a container is self-describing even when
// stripped of its Type field. Decode accepts three historical shapes for
// backward compatibility:
//
//   - Data = base64(full frame)            (current)
//   - Data = base64(bare payload), Type set (legacy offline envelope)
//   - raw nanopack payload with no container (legacy paste)
package frame

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// Type identifies the payload kind inside a frame. Aliases of the relay
// registry — one vocabulary everywhere.
type Type = relay.Type

const (
	TypeOffer    = relay.TypeOffer    // 0x01 handshake offer
	TypeAnswer   = relay.TypeAnswer   // 0x02 handshake answer
	TypeMessage  = relay.TypeMessage  // 0x03 encrypted DM (SecureMessage)
	TypeMultiMsg = relay.TypeMultiMsg // 0x04 encrypted group delivery
)

// Names maps every registered type to its canonical lowercase name (used in
// containers and logs).
var Names = map[Type]string{
	TypeOffer:    "offer",
	TypeAnswer:   "answer",
	TypeMessage:  "message",
	TypeMultiMsg: "multimsg",
}

// TypesByName inverts Names.
var TypesByName = func() map[string]Type {
	m := make(map[string]Type, len(Names))
	for t, n := range Names {
		m[n] = t
	}
	return m
}()

// Valid reports whether t is a registered type.
func Valid(t Type) bool { _, ok := Names[t]; return ok }

// Wrap builds a layer-1 frame.
func Wrap(t Type, payload []byte) []byte {
	return relay.WrapEnvelope(t, payload)
}

// Unwrap splits a layer-1 frame into its type and payload.
func Unwrap(f []byte) (Type, []byte, error) {
	if len(f) < 2 {
		return 0, nil, fmt.Errorf("frame: need type byte + payload, have %d bytes", len(f))
	}
	t := Type(f[0])
	if !Valid(t) {
		return 0, nil, fmt.Errorf("frame: unknown type byte 0x%02x", f[0])
	}
	return t, f[1:], nil
}

// ── Layer 2: the transfer container ──────────────────────────────────────────

// Container is the human-transferable form of one frame (air-gap copy/paste,
// QR, file). JSON on purpose: that boundary belongs to humans and terminals.
type Container struct {
	Type string `json:"Type"`
	Data string `json:"Data"` // base64 of the full layer-1 frame
}

// EncodeContainer wraps payload as a container whose Data is the complete
// frame (type byte included).
func EncodeContainer(t Type, payload []byte) ([]byte, error) {
	name, ok := Names[t]
	if !ok {
		return nil, fmt.Errorf("container: unregistered type 0x%02x", t)
	}
	return json.Marshal(Container{
		Type: name,
		Data: base64.StdEncoding.EncodeToString(Wrap(t, payload)),
	})
}

// Decoded is one parsed container: the frame type and bare payload.
type Decoded struct {
	Type    Type
	Payload []byte
}

// DecodeContainer accepts a pasted/file JSON container in any historical
// shape and returns the frame type plus BARE payload (frame byte stripped):
//
//  1. current: Data = base64(type byte + payload)
//  2. legacy:  Data = base64(payload only), Type names the kind
//
// It also accepts raw layer-1 frames (no JSON) and bare payloads when the
// leading byte disambiguates, so piping `decrypt`-style inputs through here
// just works.
func DecodeContainer(raw []byte) (*Decoded, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") {
		var c Container
		if err := json.Unmarshal([]byte(trimmed), &c); err != nil {
			return nil, fmt.Errorf("container: %w", err)
		}
		blob, err := base64.StdEncoding.DecodeString(c.Data)
		if err != nil {
			return nil, fmt.Errorf("container data: %w", err)
		}
		if len(blob) == 0 {
			return nil, fmt.Errorf("container: empty data")
		}
		// Current shape: blob IS a full frame whose first byte must be a
		// registered type. Legacy shape: blob is a bare payload whose first
		// byte is a struct field count — never 0x01..0x04 (offers start at
		// 10 fields), so the probe is unambiguous.
		if t := Type(blob[0]); Valid(t) {
			name := c.Type
			if name == "" {
				name = Names[t]
			} else if TypesByName[strings.ToLower(name)] != t {
				return nil, fmt.Errorf("container: Type %q disagrees with frame byte 0x%02x", c.Type, blob[0])
			}
			return &Decoded{Type: t, Payload: blob[1:]}, nil
		}
		lt, ok := TypesByName[strings.ToLower(c.Type)]
		if !ok {
			return nil, fmt.Errorf("container: unknown Type %q", c.Type)
		}
		return &Decoded{Type: lt, Payload: blob}, nil
	}

	// Not JSON: raw bytes. Full frame if the first byte is a known type,
	// otherwise we cannot guess a bare payload's kind.
	blob := []byte(trimmed)
	if t := Type(blob[0]); Valid(t) {
		return &Decoded{Type: t, Payload: blob[1:]}, nil
	}
	return nil, fmt.Errorf("container: input is neither a container nor a framed payload")
}
