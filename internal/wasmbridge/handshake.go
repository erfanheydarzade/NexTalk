//go:build js && wasm

// Mirrors client.Client's CreateOffer/AcceptOffer/FinishHandshake — same
// core.Engine calls, same session bookkeeping, just against in-memory
// state instead of an *os.File-backed client.Client.
package wasmbridge

import (
	"fmt"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/core"
)

// jsCreateOffer(peerId) -> { offer: base64(json) }
func jsCreateOffer(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Id == "" {
		return failStr("no identity loaded")
	}
	peerId := argStr(args, 0)

	peer, offerJSON, err := st.eng.CreateOffer(
		st.Id, st.IdentityPrivate, st.IdentityPublic,
		st.DilithiumPrivate, st.DilithiumPublic,
		peerId,
	)
	if err != nil {
		return fail(err)
	}
	if peerId != "" {
		st.Sessions["pending_"+peerId] = peer
	}
	st.Sessions["pending"] = peer

	return ok(map[string]any{"offer": b64e(offerJSON)})
}

// jsAcceptOffer(offerB64) -> { senderId, answer: base64(json) }
func jsAcceptOffer(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Id == "" {
		return failStr("no identity loaded")
	}
	offerBytes, err := b64d(argStr(args, 0))
	if err != nil {
		return fail(fmt.Errorf("decode offer: %w", err))
	}

	senderID, peer, answerJSON, err := st.eng.AcceptOffer(
		st.Id, st.IdentityPrivate, st.IdentityPublic,
		st.DilithiumPrivate, st.DilithiumPublic,
		st.Sessions, offerBytes,
	)
	if err != nil {
		return fail(err)
	}
	st.Sessions[senderID] = peer

	return ok(map[string]any{"senderId": senderID, "answer": b64e(answerJSON)})
}

// jsFinishHandshake(answerB64) -> { peerId }
func jsFinishHandshake(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Id == "" {
		return failStr("no identity loaded")
	}
	answerBytes, err := b64d(argStr(args, 0))
	if err != nil {
		return fail(fmt.Errorf("decode answer: %w", err))
	}

	senderID, err := core.PeekAnswerSenderID(answerBytes)
	if err != nil {
		return fail(fmt.Errorf("peek answer header: %w", err))
	}

	peer, okp := st.Sessions["pending_"+senderID]
	if !okp {
		peer, okp = st.Sessions["pending"]
		if !okp {
			return failStr("no pending session found for " + senderID)
		}
	}

	peerID, err := st.eng.FinishHandshake(st.Id, peer, answerBytes)
	if err != nil {
		return fail(err)
	}
	delete(st.Sessions, "pending")
	delete(st.Sessions, "pending_"+peerID)
	st.Sessions[peerID] = peer

	return ok(map[string]any{"peerId": peerID})
}
