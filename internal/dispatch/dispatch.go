// Package dispatch is the single shared receive path for every NexTalk
// transport — built-in worker/proxy and external process/WASM transports
// alike.
//
// A transport delivers opaque layer-1 frames ([type byte][nanopack payload],
// see internal/frame). Dispatch unwraps one frame, runs the cryptographic
// protocol step (handshake/message/group), persists the result into the
// identity's mailbox/fanout stores, and returns an Event describing what
// happened. Replies (handshake answers) go out through Sender, a callback
// the caller binds to its own transport:
//
//	worker CLI/GUI  → relay.SendEnvelope over relay.Relay
//	external poll   → FrameTransport.SendFrame
//
// Transports never touch keys, sessions, or stores directly; all of that
// lives here, in the trusted core.
package dispatch

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// Event describes one dispatched frame. JSON shape matches the historic
// `worker listen` events so scripts keep working across transports.
type Event struct {
	Type     string   `json:"type"`
	Peer     string   `json:"peer,omitempty"`
	Sender   string   `json:"sender,omitempty"`
	Encoding string   `json:"encoding,omitempty"`
	Message  string   `json:"message,omitempty"`
	Context  string   `json:"context,omitempty"`
	Actions  []Action `json:"actions,omitempty"`
}

// Action records an automatic follow-up the dispatcher performed.
type Action struct {
	Type string `json:"type"`
	Peer string `json:"peer,omitempty"`
}

// Sender delivers a reply frame toward recipientPub (raw 32B Ed25519).
type Sender func(ctx context.Context, recipientPub []byte, t relay.Type, payload []byte) error

// Deps carries the trusted state dispatch mutates. Mailbox and Fanout may
// be nil (events still returned, persistence skipped); Client is required.
type Deps struct {
	Client  *Client.Client
	Mailbox *mailbox.Store
	Fanout  *multimsg.Fanout
}

// OpenDeps opens the identity's persistent stores and wires a receive-only
// fanout (nil relay: ProcessDelivery never sends). Mirrors the shell/CLI
// store layout so every transport shares one history.
func OpenDeps(cl *Client.Client) *Deps {
	d := &Deps{Client: cl}
	if st, err := mailbox.Load(cl.Id); err == nil {
		d.Mailbox = st
	}
	ctxStore, deliveryStore, err := multimsg.OpenIdentityStores(cl.Id)
	if err != nil {
		ctxStore = multimsg.NewMemoryContextStore()
		deliveryStore = multimsg.NewMemoryDeliveryStore()
	}
	d.Fanout = multimsg.NewFanout(cl, nil, ctxStore, deliveryStore, multimsg.DefaultFanoutConfig())
	return d
}

// DispatchFrame routes one raw layer-1 frame and returns its event.
// A nil event with nil error means "duplicate delivery, already shown".
func DispatchFrame(ctx context.Context, cl *Client.Client, selfPriv ed25519.PrivateKey, body []byte, d *Deps, send Sender) (*Event, error) {
	if cl == nil {
		return nil, fmt.Errorf("dispatch: nil client")
	}
	t, data, err := frame.Unwrap(body)
	if err != nil {
		return nil, fmt.Errorf("dispatch: unwrap envelope: %w", err)
	}
	switch t {
	case relay.TypeOffer:
		return handleOffer(ctx, cl, send, selfPriv, data)
	case relay.TypeAnswer:
		return handleAnswer(cl, data)
	case relay.TypeMessage:
		return handleMessage(cl, data, d)
	case relay.TypeMultiMsg:
		return handleMultiMessage(cl, data, d)
	default:
		return nil, fmt.Errorf("dispatch: unknown envelope type: %d", t)
	}
}

// DispatchBatch dispatches many frames, collecting per-frame errors as
// error events instead of aborting — every frame is accounted for.
func DispatchBatch(ctx context.Context, cl *Client.Client, selfPriv ed25519.PrivateKey, frames [][]byte, d *Deps, send Sender) []Event {
	events := make([]Event, 0, len(frames))
	for _, f := range frames {
		ev, err := DispatchFrame(ctx, cl, selfPriv, f, d, send)
		if err != nil {
			events = append(events, Event{Type: "error", Message: err.Error()})
			continue
		}
		if ev != nil {
			events = append(events, *ev)
		}
	}
	return events
}

func handleOffer(ctx context.Context, cl *Client.Client, send Sender, selfPriv ed25519.PrivateKey, data []byte) (*Event, error) {
	offer, err := core.DecodeOffer(data)
	if err != nil {
		return nil, fmt.Errorf("decode offer: %w", err)
	}
	answerBytes, err := cl.AcceptOffer(data)
	if err != nil {
		return nil, fmt.Errorf("accept offer: %w", err)
	}
	if send == nil {
		return nil, fmt.Errorf("offer received but no sender bound")
	}
	if err := send(ctx, offer.IdPub, relay.TypeAnswer, answerBytes); err != nil {
		return nil, fmt.Errorf("send answer: %w", err)
	}
	// Peer is the sender's peer ID (not the raw pubkey hex): it is what
	// completion, contacts, and every follow-up command resolve.
	peer := offer.SenderId
	return &Event{
		Type: "offer",
		Peer: peer,
		Actions: []Action{
			{Type: "answer_sent", Peer: peer},
		},
	}, nil
}

func handleAnswer(cl *Client.Client, data []byte) (*Event, error) {
	peerID, err := cl.FinishHandshake(data)
	if err != nil {
		return nil, fmt.Errorf("finish handshake: %w", err)
	}
	return &Event{
		Type: "answer",
		Peer: peerID,
		Actions: []Action{
			{Type: "session_established", Peer: peerID},
		},
	}, nil
}

func handleMessage(cl *Client.Client, data []byte, d *Deps) (*Event, error) {
	senderID, plaintext, err := cl.Decrypt(data)
	if err != nil {
		if errors.Is(err, crypto.ErrReplay) {
			return nil, fmt.Errorf("incoming message %s", describeDecryptError(err))
		}
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	event := &Event{Type: "message", Sender: senderID}
	if utf8.Valid(plaintext) {
		event.Encoding = "utf-8"
		event.Message = string(plaintext)
	} else {
		event.Encoding = "base64"
		event.Message = base64.StdEncoding.EncodeToString(plaintext)
	}
	if d != nil && d.Mailbox != nil {
		if err := d.Mailbox.AppendIncoming(senderID, event.Message); err != nil {
			return event, fmt.Errorf("store incoming message: %w", err)
		}
	}
	return event, nil
}

func handleMultiMessage(cl *Client.Client, data []byte, d *Deps) (*Event, error) {
	if d == nil || d.Fanout == nil {
		return nil, fmt.Errorf("group message received but fanout unavailable")
	}
	inbound, err := d.Fanout.ProcessDelivery(cl.Id, data)
	if err != nil {
		if errors.Is(err, multimsg.ErrDuplicateDelivery) {
			return nil, nil // Already shown — stay silent on redelivery.
		}
		return nil, fmt.Errorf("group message %s", describeDecryptError(err))
	}
	body := string(inbound.Plaintext)
	if !utf8.Valid(inbound.Plaintext) {
		body = base64.StdEncoding.EncodeToString(inbound.Plaintext)
	}
	if d.Mailbox != nil {
		if err := d.Mailbox.AppendGroupIncoming(
			string(inbound.ContextID()),
			inbound.DisplayName(),
			inbound.Sender,
			body,
		); err != nil {
			return nil, fmt.Errorf("store group message: %w", err)
		}
	}
	return &Event{
		Type:    "group_message",
		Sender:  inbound.Sender,
		Context: inbound.DisplayName(),
		Message: body,
	}, nil
}

// describeDecryptError translates crypto failures into actionable text.
func describeDecryptError(err error) string {
	if errors.Is(err, crypto.ErrReplay) {
		return "rejected: the sender's session state was rolled back " +
			"(two NexTalk processes sharing their identity?) — have them run 'connect' again"
	}
	return err.Error()
}
