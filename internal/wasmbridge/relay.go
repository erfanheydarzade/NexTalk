//go:build js && wasm

// Live relay transport for the wasm build.
//
// This deliberately does NOT reimplement HTTP: internal/relay/worker.Adapter
// already talks to the Router/shard network purely over net/http, and Go's
// net/http has transparently used the browser's fetch() API under
// GOOS=js GOARCH=wasm since Go 1.21 (see net/http/roundtrip_js.go in the Go
// source tree). So the *exact* same Adapter the CLI's `nextalk worker`
// transport uses (cmd/worker/register.go -> workerrelay.New) is reused here
// unmodified — no separate wasm-flavoured HTTP client, no duplicated
// Router/shard/replica logic to keep in sync.
//
// Framing is likewise shared, not reinvented: SendEnvelope/WrapEnvelope/
// PeerIDToEd25519Pub now live in internal/relay (promoted out of the
// formerly cmd/worker-private envolpe.go — see that file's comments), and
// UnwrapEnvelope stays exported on the worker package where it always was.
// That is what "standard functions and parameters, same as the worker
// part" means concretely: cmd/worker and this package both call
// relay.SendEnvelope(ctx, r, priv, pub, type, data) and both unwrap with
// workerrelay.UnwrapEnvelope(body) — one implementation, two callers.
//
// The proxy transport (internal/relay/proxy.Adapter) is NOT wired up here:
// its Send method's signature doesn't actually satisfy relay.Relay (it's
// missing the senderPriv parameter the interface requires), so nothing in
// the existing codebase can use it polymorphically today, worker transport
// included. That's a pre-existing gap in cmd/proxy, not something
// introduced by the wasm build — flagging it rather than silently working
// around it.
package wasmbridge

import (
	"context"
	"fmt"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
)

// jsConnectWorker(routerURL) -> { ok: true }
// Wires up the same Router/shard relay the CLI's `nextalk worker` transport
// uses. Cheap to call repeatedly (New only parses the URL); safe to call
// again to point at a different Router.
func jsConnectWorker(this js.Value, args []js.Value) any {
	routerURL := argStr(args, 0)

	a, err := workerrelay.New(routerURL)
	if err != nil {
		return fail(err)
	}

	st.mu.Lock()
	st.relayConn = a
	st.relayKind = "worker"
	st.mu.Unlock()

	return ok(map[string]any{"ok": true})
}

// jsDisconnectRelay() -> { ok: true }
func jsDisconnectRelay(this js.Value, args []js.Value) any {
	st.mu.Lock()
	st.relayConn = nil
	st.relayKind = ""
	st.mu.Unlock()
	return ok(map[string]any{"ok": true})
}

// jsRelayStatus() -> { connected, kind }
func jsRelayStatus(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()
	return ok(map[string]any{
		"connected": st.relayConn != nil,
		"kind":      st.relayKind,
	})
}

// jsRegisterWithRelay() -> { pubkey }
// Proves ownership of the active identity to the Router (mints/reuses a
// mailbox capability behind the scenes). Not strictly required before
// send/receive — both call Register internally too — but calling it up
// front surfaces connectivity/identity problems immediately instead of on
// the first real send.
func jsRegisterWithRelay(this js.Value, args []js.Value) any {
	st.mu.Lock()
	r, priv := st.relayConn, st.IdentityPrivate
	st.mu.Unlock()

	if r == nil {
		return failStr("not connected — call connectWorker(routerUrl) first")
	}
	pubHex, err := r.Register(context.Background(), priv)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"pubkey": pubHex})
}

// jsSendOffer(peerId, offerB64)   -> { ok: true }
// jsSendAnswer(peerId, answerB64) -> { ok: true }
// jsSendMessage(peerId, cipherB64)-> { ok: true }
//
// peerId is the RECIPIENT — the same argument createOffer/acceptOffer
// already produced a session for. Each wraps the given base64 payload
// (already produced by createOffer/acceptOffer/encrypt above) in the
// same [1 type byte][data] envelope cmd/worker uses and sends it via
// relay.SendEnvelope, which signs it with the active identity internally.
func jsSendOffer(this js.Value, args []js.Value) any {
	return sendEnvelopeJS(args, relay.TypeOffer)
}

func jsSendAnswer(this js.Value, args []js.Value) any {
	return sendEnvelopeJS(args, relay.TypeAnswer)
}

func jsSendMessage(this js.Value, args []js.Value) any {
	return sendEnvelopeJS(args, relay.TypeMessage)
}

func sendEnvelopeJS(args []js.Value, t relay.Type) any {
	st.mu.Lock()
	r, priv := st.relayConn, st.IdentityPrivate
	st.mu.Unlock()

	if r == nil {
		return failStr("not connected — call connectWorker(routerUrl) first")
	}

	peerId := argStr(args, 0)
	payload, err := b64d(argStr(args, 1))
	if err != nil {
		return fail(fmt.Errorf("decode payload: %w", err))
	}

	pub, err := relay.PeerIDToEd25519Pub(peerId)
	if err != nil {
		return fail(err)
	}

	if err := relay.SendEnvelope(context.Background(), r, priv, pub, t, payload); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// jsReceive() -> { envelopes: [{ type, data }, ...] }
// Drains our mailbox and unwraps each frame, but does NOT route it —
// that's on JS. This is the low-level building block; most callers want
// jsListen (listen.go) instead, which mirrors `nextalk worker listen`
// and auto-dispatches (accepts offers and answers them, finishes
// handshakes, decrypts messages) instead of handing raw frames back.
// `type` is 1 = offer, 2 = answer, 3 = message; `data` is base64 and
// goes straight into acceptOffer(data) / finishHandshake(data) /
// decrypt(data) as-is. A malformed frame is skipped rather than failing
// the whole batch.
func jsReceive(this js.Value, args []js.Value) any {
	st.mu.Lock()
	r, priv := st.relayConn, st.IdentityPrivate
	st.mu.Unlock()

	if r == nil {
		return failStr("not connected — call connectWorker(routerUrl) first")
	}

	msgs, err := r.Receive(context.Background(), priv)
	if err != nil {
		return fail(err)
	}

	envelopes := make([]any, 0, len(msgs))
	for _, m := range msgs {
		t, data, err := workerrelay.UnwrapEnvelope(m.Body)
		if err != nil {
			continue
		}
		envelopes = append(envelopes, map[string]any{
			"type": int(t),
			"data": b64e(data),
		})
	}
	return ok(map[string]any{"envelopes": envelopes})
}
