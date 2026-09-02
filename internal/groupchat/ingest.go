// internal/groupchat/ingest.go — receiving side of the framing standard for
// transports without a live poll loop (offline copy/paste, manual proxy).
//
// Ingest classifies one blob of user-provided bytes (a transfer Container, a
// raw layer-1 frame, or a bare legacy payload), processes group deliveries
// through the Fanout pipeline, decrypts plain messages, records both into
// the persistent mailbox, and returns what to display.
package groupchat

import (
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
)

// IngestEvent describes one processed inbound item.
type IngestEvent struct {
	Kind      string // "group_message" | "message" | "duplicate"
	Sender    string
	Context   string // group display name (group messages only)
	ContextID string
	Message   string
}

// ErrNotFrame reports input that is neither a container nor a framed
// payload — callers should fall back to their transport's legacy handling.
var ErrNotFrame = fmt.Errorf("input is not a NexTalk transfer container or frame")

// Ingest processes raw user-supplied bytes against an identity.
//
//   - cl         : loaded identity (sessions for decryption)
//   - mb         : persistent mailbox (may be nil — nothing is recorded)
//   - fan        : fanout built over the identity's stores (needed for 0x04)
//   - raw        : container JSON, full frame, or bare legacy payload
//
// Returns ErrNotFrame when the input cannot be classified; callers decide
// whether that is an error or a signal to try another decoder.
func Ingest(cl *Client.Client, mb *mailbox.Store, fan *multimsg.Fanout, raw []byte) (*IngestEvent, error) {
	dec, err := frame.DecodeContainer(raw)
	if err != nil {
		return nil, ErrNotFrame
	}

	switch dec.Type {

	case frame.TypeMultiMsg:
		if fan == nil {
			return nil, fmt.Errorf("group delivery received but no identity/stores are loaded")
		}
		inbound, err := fan.ProcessDelivery(cl.Id, dec.Payload)
		if err != nil {
			// Two benign "already have this" paths reach the operator as
			// duplicates: an identical frame is rejected by the ratchet,
			// and a fresh re-encryption of a seen Message ID by dedup.
			if errors.Is(err, multimsg.ErrDuplicateDelivery) ||
				errors.Is(err, crypto.ErrReplay) {
				return &IngestEvent{Kind: "duplicate"}, nil
			}
			return nil, err
		}
		body := decodeText(inbound.Plaintext)
		if mb != nil {
			if err := mb.AppendGroupIncoming(
				string(inbound.ContextID()), inbound.DisplayName(),
				inbound.Sender, body,
			); err != nil {
				return nil, fmt.Errorf("store group message: %w", err)
			}
		}
		return &IngestEvent{
			Kind:      "group_message",
			Sender:    inbound.Sender,
			Context:   inbound.DisplayName(),
			ContextID: string(inbound.ContextID()),
			Message:   body,
		}, nil

	case frame.TypeMessage:
		senderID, plain, err := cl.Decrypt(dec.Payload)
		if err != nil {
			return nil, err
		}
		body := decodeText(plain)
		if mb != nil {
			if err := mb.AppendIncoming(senderID, body); err != nil {
				return nil, fmt.Errorf("store message: %w", err)
			}
		}
		return &IngestEvent{Kind: "message", Sender: senderID, Message: body}, nil

	default:
		return nil, fmt.Errorf("received %s frame — use offer/accept/finish for handshake steps",
			frame.Names[dec.Type])
	}
}

func decodeText(pt []byte) string {
	if utf8.Valid(pt) {
		return string(pt)
	}
	return base64.StdEncoding.EncodeToString(pt)
}
