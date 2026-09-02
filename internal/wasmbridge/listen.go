//go:build js && wasm

// Auto-dispatching poll, mirroring cmd/worker/listen.go's RunListen and
// its dispatch/handleOffer/handleAnswer/handleMessage helpers: drains the
// mailbox, accepts offers (and sends the answer back automatically),
// finishes handshakes, and decrypts messages — instead of leaving all of
// that to JS the way relay.go's lower-level receive() does.
//
// The event shape ({type, peer, sender, encoding, message, actions}) is
// the same as cmd/worker's ListenEvent/ListenAction JSON, so anything
// already parsing `nextalk worker listen --format json` output can parse
// NexTalk.relay.listen()'s output too. This is what "standard functions
// and parameters, same as the worker part" means for the highest-level
// call in the relay surface, not just the low-level Send/Receive plumbing.
package wasmbridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall/js"
	"unicode/utf8"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	"golang.org/x/crypto/ed25519"
)

// jsListen() -> Promise<{ events: [...] }>
// One poll-and-dispatch pass, same as `nextalk worker listen`. A browser
// tab can't block the main thread waiting on network the way a CLI
// process can, so this is meant to be called on an interval from JS (see
// the Listen button in web/index.html) rather than expecting it to block.
// This function returns a JS Promise to avoid deadlocking the Wasm main thread.
func jsListen(this js.Value, args []js.Value) any {
	st.mu.Lock()
	r, priv, id := st.relayConn, st.IdentityPrivate, st.Id
	st.mu.Unlock()

	if r == nil {
		return failStr("not connected — call connectWorker(routerUrl) first")
	}
	if id == "" {
		return failStr("no identity loaded")
	}

	ctx := context.Background()
	msgs, err := r.Receive(ctx, priv)
	if err != nil {
		return fail(fmt.Errorf("receive: %w", err))
	}

	events := make([]any, 0, len(msgs))
	for _, m := range msgs {
		event, err := dispatchEnvelope(ctx, r, priv, m.Body)
		if err != nil {
			// Collect dispatch errors as events rather than aborting the
			// batch, same as RunListen — one bad frame shouldn't hide the
			// rest of the mailbox.
			events = append(events, map[string]any{"type": "error", "message": err.Error()})
			continue
		}
		if event != nil {
			events = append(events, event)
		}
	}
	return ok(map[string]any{"events": events})
}

// dispatchEnvelope routes one raw relay.Message body, exactly like
// cmd/worker/listen.go's dispatch.
func dispatchEnvelope(ctx context.Context, r relay.Relay, selfPriv ed25519.PrivateKey, body []byte) (map[string]any, error) {
	t, data, err := workerrelay.UnwrapEnvelope(body)
	if err != nil {
		return nil, fmt.Errorf("unwrap envelope: %w", err)
	}

	switch t {
	case relay.TypeOffer:
		return handleOfferEnvelope(ctx, r, selfPriv, data)
	case relay.TypeAnswer:
		return handleAnswerEnvelope(data)
	case relay.TypeMessage:
		return handleMessageEnvelope(data)
	case relay.TypeMultiMsg:
		return handleGroupMessageEnvelope(data)
	default:
		return nil, fmt.Errorf("unknown envelope type: %d", t)
	}
}

// handleOfferEnvelope mirrors cmd/worker/listen.go's handleOffer: accept
// the offer against our session map, then send the answer straight back
// to the sender's identity pubkey (offer.IdPub — no peer-ID roundtrip
// needed here, we already have the raw key from the offer itself).
func handleOfferEnvelope(ctx context.Context, r relay.Relay, selfPriv ed25519.PrivateKey, data []byte) (map[string]any, error) {
	offer, err := core.DecodeOffer(data)
	if err != nil {
		return nil, fmt.Errorf("decode offer: %w", err)
	}

	st.mu.Lock()
	senderID, peer, answerJSON, err := st.eng.AcceptOffer(
		st.Id, st.IdentityPrivate, st.IdentityPublic,
		st.DilithiumPrivate, st.DilithiumPublic,
		st.Sessions, data,
	)
	if err == nil {
		st.Sessions[senderID] = peer
	}
	st.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("accept offer: %w", err)
	}

	if err := relay.SendEnvelope(ctx, r, selfPriv, offer.IdPub, relay.TypeAnswer, answerJSON); err != nil {
		return nil, fmt.Errorf("send answer: %w", err)
	}

	return map[string]any{
		"type": "offer",
		"peer": hex.EncodeToString(offer.IdPub),
		"actions": []any{
			map[string]any{"type": "answer_sent", "peer": hex.EncodeToString(offer.IdPub)},
		},
	}, nil
}

// handleAnswerEnvelope mirrors cmd/worker/listen.go's handleAnswer.
func handleAnswerEnvelope(data []byte) (map[string]any, error) {
	senderID, err := core.PeekAnswerSenderID(data)
	if err != nil {
		return nil, fmt.Errorf("peek answer header: %w", err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	peer, okp := st.Sessions["pending_"+senderID]
	if !okp {
		peer, okp = st.Sessions["pending"]
		if !okp {
			return nil, fmt.Errorf("no pending session found for %s", senderID)
		}
	}

	peerID, err := st.eng.FinishHandshake(st.Id, peer, data)
	if err != nil {
		return nil, fmt.Errorf("finish handshake: %w", err)
	}
	delete(st.Sessions, "pending")
	delete(st.Sessions, "pending_"+peerID)
	st.Sessions[peerID] = peer

	return map[string]any{
		"type": "answer",
		"peer": peerID,
		"actions": []any{
			map[string]any{"type": "session_established", "peer": peerID},
		},
	}, nil
}

// handleMessageEnvelope mirrors cmd/worker/listen.go's handleMessage.
func handleMessageEnvelope(data []byte) (map[string]any, error) {
	claimedSender, err := crypto.SenderIDFromFrame(data)
	if err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// Fix: check pending or active sessions so messages coming in right
	// after a handshake completion don't fail lookup.
	session, exists := st.Sessions[claimedSender]
	if !exists {
		if pendingPeer, okp := st.Sessions["pending_"+claimedSender]; okp {
			session = pendingPeer
		} else if pendingPeer, okp := st.Sessions["pending"]; okp {
			session = pendingPeer
		} else {
			return nil, fmt.Errorf("no active session with peer %s", claimedSender)
		}
	}
	senderID, plaintext, err := session.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	event := map[string]any{"type": "message", "sender": senderID}
	if utf8.Valid(plaintext) {
		event["encoding"] = "utf-8"
		event["message"] = string(plaintext)
	} else {
		event["encoding"] = "base64"
		event["message"] = base64.StdEncoding.EncodeToString(plaintext)
	}
	return event, nil
}

// handleGroupMessageEnvelope processes an inbound multi-message (0x04)
// delivery end-to-end — the browser equivalent of the shell's TypeMultiMsg
// dispatch and `nextalk worker listen`'s group_message event:
//
//	decrypt over the 1:1 session → parse the embedded binding → verify the
//	delivery was not transplanted → adopt the creator-signed group metadata
//	(so JS learns the display name straight from the message) → dedupe
//	redeliveries → emit a group_message event.
func handleGroupMessageEnvelope(data []byte) (map[string]any, error) {
	st.mu.Lock()
	if st.Fanout == nil || st.ContextStore == nil {
		ensureFanoutLocked()
	}
	fanout := st.Fanout
	selfID := st.Id
	st.mu.Unlock()

	if fanout == nil {
		return nil, fmt.Errorf("group message received but no identity is loaded")
	}

	inbound, err := fanout.ProcessDelivery(selfID, data)
	if err != nil {
		if errors.Is(err, multimsg.ErrDuplicateDelivery) {
			// Already delivered in this page's lifetime; not worth surfacing.
			return nil, nil
		}
		return nil, fmt.Errorf("group message %s", err.Error())
	}

	body := string(inbound.Plaintext)
	encoding := "utf-8"
	if !utf8.Valid(inbound.Plaintext) {
		body = base64.StdEncoding.EncodeToString(inbound.Plaintext)
		encoding = "base64"
	}

	event := map[string]any{
		"type":       "group_message",
		"sender":     inbound.Sender,
		"context_id": string(inbound.ContextID()),
		"context":    inbound.DisplayName(),
		"message":    body,
		"encoding":   encoding,
		"message_id": string(inbound.Meta.MessageID),
	}
	return event, nil
}
