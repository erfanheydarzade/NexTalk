//go:build js && wasm

// Auto-dispatching poll, mirroring cmd/worker/listen.go's RunListen: drains
// the mailbox, accepts offers (and sends the answer back automatically),
// finishes handshakes, and decrypts messages — instead of leaving all of
// that to JS the way relay.go's lower-level receive() does.
//
// The receive path is NOT implemented here: every frame goes through
// internal/dispatch, the single shared dispatcher also used by
// `nextalk worker listen`, the shell, and NexTalk.transport.poll(). Same
// code, so the events ({type, peer, sender, encoding, message, actions,
// pubkey, context_id, message_id}) and the dedupe of redelivered group
// messages are identical whichever transport the frames arrived on.
package wasmbridge

import (
	"context"
	"fmt"
	"sync"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// dispatchMu serialises dispatch against other users of st.ActiveClient's
// session map (relay.listen and transport.poll share it). It is held while
// dispatch may send an answer; that is safe because no synchronous
// js.FuncOf ever takes it.
var dispatchMu sync.Mutex

// dispatchDepsLocked builds the receive-side dependencies from the active
// identity. Caller holds st.mu. Mailbox is nil on purpose: persistence is
// the page's job (there is no filesystem), and events carry everything
// needed to store a message.
func dispatchDepsLocked() *dispatch.Deps {
	ensureFanoutLocked()
	return &dispatch.Deps{Client: st.ActiveClient, Fanout: st.Fanout}
}

// jsListen() -> Promise<{ events: [...] }>
// One poll-and-dispatch pass, same as `nextalk worker listen`. A browser
// tab can't block the main thread waiting on network the way a CLI
// process can, so this is meant to be called on an interval from JS (see
// the Listen button in web/index.html) rather than expecting it to block.
// This function returns a JS Promise to avoid deadlocking the Wasm main thread.
func jsListen(this js.Value, args []js.Value) any {
	st.mu.Lock()
	r, priv, id, cl := st.relayConn, st.IdentityPrivate, st.Id, st.ActiveClient
	st.mu.Unlock()

	if r == nil {
		return failStr("not connected — call connectWorker(routerUrl) first")
	}
	if id == "" || cl == nil {
		return failStr("no identity loaded")
	}

	ctx := context.Background()
	msgs, err := r.Receive(ctx, priv)
	if err != nil {
		return fail(fmt.Errorf("receive: %w", err))
	}

	st.mu.Lock()
	deps := dispatchDepsLocked()
	st.mu.Unlock()

	frames := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		frames = append(frames, m.Body)
	}
	send := func(ctx context.Context, recipientPub []byte, t relay.Type, payload []byte) error {
		return relay.SendEnvelope(ctx, r, priv, recipientPub, t, payload)
	}

	dispatchMu.Lock()
	// One bad frame becomes an {type:"error"} event; the rest of the
	// mailbox is still processed (same as RunListen).
	events := dispatch.DispatchBatch(ctx, cl, priv, frames, deps, send)
	dispatchMu.Unlock()

	out := make([]any, 0, len(events))
	for _, e := range events {
		out = append(out, e)
	}
	return ok(map[string]any{"events": out})
}
