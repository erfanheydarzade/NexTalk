// internal/multimsg/wire.go
//
// Wire format for group (multi-message) delivery payloads.
//
// A delivery is encrypted twice, at two layers:
//
//  1. The relay envelope frames it as TypeMultiMsg (0x04).
//  2. The inner ciphertext is produced by the sender's 1:1 Double Ratchet
//     session with the recipient.
//
// What this file concerns itself with is the *plaintext of layer 2* —
// the "wrapped payload". Two formats exist:
//
//	v1 (legacy):  AAD || plaintext
//	v2 (current): 0x02 || AAD || lenPref(signed context descriptor) || plaintext
//
// where AAD is the canonical binding built by buildDeliveryAAD:
//
//	lenPref(msgID) || lenPref(ctxID) || lenPref(sender) || lenPref(recipient) || uint64be(version)
//
// The AAD travels inside the encrypted payload so the recipient can parse it,
// learn which group/message the delivery belongs to, and verify that the
// ciphertext was not transplanted from another conversation. v2 additionally
// carries the creator-signed MessageContext so recipients can discover the
// group's display name without an out-of-band channel. The leading byte
// disambiguates the formats: legacy payloads always start with
// len(msgID)=32 (hex-encoded), never 0x02.
package multimsg

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/erfanheydarzade/nanopack"
)

// wireVersionV2 marks payloads that embed the signed context descriptor.
const wireVersionV2 byte = 0x02

// DeliveryMeta is the per-delivery binding parsed from the wrapped payload.
type DeliveryMeta struct {
	MessageID MessageID
	ContextID ContextID
	Sender    string
	Recipient string
	Version   uint64
}

// Parsed is the decoded form of a wrapped payload.
type Parsed struct {
	Meta      DeliveryMeta
	Context   *MessageContext // nil for legacy (v1) senders
	Plaintext []byte
}

// ParseWrapped decodes a decrypted delivery payload in either wire format.
// It verifies the embedded context signature when present; binding checks
// against the authenticated sender/recipient live in Fanout.ProcessDelivery.
func ParseWrapped(wrapped []byte) (*Parsed, error) {
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("empty wrapped payload")
	}

	if wrapped[0] == wireVersionV2 {
		meta, rest, err := parseAAD(wrapped[1:])
		if err != nil {
			return nil, err
		}
		ctxBin, rest, err := readLengthPrefixed(rest)
		if err != nil {
			return nil, fmt.Errorf("context descriptor: %w", err)
		}
		p := &Parsed{Meta: meta, Plaintext: rest}
		if len(ctxBin) > 0 {
			ctx := &MessageContext{}
			if err := nanopack.UnmarshalFastID(ctxBin, ctx); err != nil {
				return nil, fmt.Errorf("unmarshal context descriptor: %w", err)
			}
			if err := VerifyContextSignature(ctx); err != nil {
				return nil, fmt.Errorf("context descriptor rejected: %w", err)
			}
			p.Context = ctx
		}
		return p, nil
	}

	// Legacy v1: AAD || plaintext.
	meta, rest, err := parseAAD(wrapped)
	if err != nil {
		return nil, err
	}
	return &Parsed{Meta: meta, Plaintext: rest}, nil
}

// parseAAD parses the canonical length-prefixed AAD fields plus the trailing
// big-endian version, returning the remainder (the plaintext).
func parseAAD(buf []byte) (DeliveryMeta, []byte, error) {
	var meta DeliveryMeta
	var err error

	var msgID, ctxID string
	if msgID, buf, err = readLengthPrefixedString(buf); err != nil {
		return meta, nil, fmt.Errorf("msg id: %w", err)
	}
	if ctxID, buf, err = readLengthPrefixedString(buf); err != nil {
		return meta, nil, fmt.Errorf("context id: %w", err)
	}
	if meta.Sender, buf, err = readLengthPrefixedString(buf); err != nil {
		return meta, nil, fmt.Errorf("sender: %w", err)
	}
	if meta.Recipient, buf, err = readLengthPrefixedString(buf); err != nil {
		return meta, nil, fmt.Errorf("recipient: %w", err)
	}
	if len(buf) < 8 {
		return meta, nil, fmt.Errorf("version: need 8 bytes, have %d", len(buf))
	}
	meta.MessageID = MessageID(msgID)
	meta.ContextID = ContextID(ctxID)
	meta.Version = binary.BigEndian.Uint64(buf[:8])
	return meta, buf[8:], nil
}

func readLengthPrefixed(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 1 {
		return nil, nil, fmt.Errorf("need length byte")
	}
	n := int(buf[0])
	if len(buf) < 1+n {
		return nil, nil, fmt.Errorf("field truncated: want %d bytes, have %d", n, len(buf)-1)
	}
	return buf[1 : 1+n], buf[1+n:], nil
}

func readLengthPrefixedString(buf []byte) (string, []byte, error) {
	data, rest, err := readLengthPrefixed(buf)
	return string(data), rest, err
}

// VerifyContextSignature verifies the context signature by resolving the
// creator's Ed25519 public key from the CreatorID peer ID (whose first 32
// bytes ARE the Ed25519 public key). This authenticates both the metadata
// contents and the claim that it originates from CreatorID — an untrusted
// relay or peer cannot forge or rename a group they do not control.
func VerifyContextSignature(ctx *MessageContext) error {
	if ctx == nil {
		return fmt.Errorf("nil context")
	}
	if len(ctx.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length")
	}
	pub, err := relay.PeerIDToEd25519Pub(ctx.CreatorID)
	if err != nil {
		return fmt.Errorf("resolve creator %s: %w", ctx.CreatorID, err)
	}
	payload, err := signContextPayload(ctx)
	if err != nil {
		return fmt.Errorf("marshal context for verification: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, ctx.Signature) {
		return fmt.Errorf("context signature verification failed for creator %s", ctx.CreatorID)
	}
	return nil
}

// wrapPayloadV2 builds the current wrapped-payload representation:
// version byte + AAD + length-prefixed context descriptor + plaintext.
// The descriptor is always present (zero-length when the sender has no
// metadata) so payloads stay self-describing.
func wrapPayloadV2(aad []byte, msgCtx *MessageContext, plaintext []byte) ([]byte, error) {
	out := make([]byte, 0, 1+len(aad)+len(plaintext)+96)
	out = append(out, wireVersionV2)
	out = append(out, aad...)
	if msgCtx != nil {
		ctxBin, err := nanopack.MarshalFastID(msgCtx)
		if err != nil {
			return nil, fmt.Errorf("marshal context descriptor: %w", err)
		}
		if len(ctxBin) > 255 {
			return nil, fmt.Errorf("context descriptor too large: %d bytes", len(ctxBin))
		}
		out = append(out, byte(len(ctxBin)))
		out = append(out, ctxBin...)
	} else {
		out = append(out, 0)
	}
	out = append(out, plaintext...)
	return out, nil
}
