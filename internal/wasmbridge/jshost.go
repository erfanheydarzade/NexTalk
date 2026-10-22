//go:build js && wasm

// JS-backed FrameTransport.
//
// Runtime choice (documented in docs/wasm.md): wazero is NOT used in the
// browser build. I could not verify that wazero's interpreter builds and
// runs under GOOS=js GOARCH=wasm, so internal/transport/wasm.go is compiled
// out of js builds (//go:build !js, stub in wasm_js.go) and the identical
// ABI v1 — (ptr,len) args, ptr<<32|len results, BE32-prefixed poll blobs —
// is implemented on the JS side with the browser's own
// WebAssembly.instantiate (web/wasm/ntx-host.js). Go sees a FrameTransport
// whose methods call into that JS object.
//
// The JS handle contract (what NexTalk.transport._registerHost receives):
//
//	host.instantiate(id, wasmU8, cfgU8) -> Promise<handle>   // runs ntx_init
//	handle.caps          string, CSV from ntx_caps
//	handle.start()/stop()                -> int rc
//	handle.send(frameU8, recipientU8)    -> int rc
//	handle.attach(mailboxU8, secretU8)   -> int rc
//	handle.detach(mailboxU8)             -> int rc
//	handle.poll(limit, mailboxU8|null)   -> Uint8Array blob (BE32-prefixed frames)
//	handle.status()                      -> int (1 running)
//	handle.destroy()
//
// Only instantiate is async (browsers refuse large synchronous compiles on
// the main thread); every other call is synchronous, so Go may call them
// from inside a js.FuncOf callback without risking the fetch-deadlock.
package wasmbridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/ntxhost"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

var (
	wasmHostMu sync.Mutex
	wasmHost   js.Value // zero Value (undefined) until _registerHost
)

// jsRegisterHost(impl) -> { ok }
func jsRegisterHost(this js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeObject || args[0].Get("instantiate").Type() != js.TypeFunction {
		return failStr("host must be an object with an instantiate(id, wasm, cfg) function")
	}
	wasmHostMu.Lock()
	wasmHost = args[0]
	wasmHostMu.Unlock()
	return ok(map[string]any{"ok": true})
}

// awaitJS blocks the calling goroutine until the promise settles. It must
// run on a goroutine, never directly inside a js.FuncOf callback (every
// caller reaches it through async()).
func awaitJS(p js.Value) (js.Value, error) {
	type res struct {
		v   js.Value
		err error
	}
	ch := make(chan res, 1)
	then := js.FuncOf(func(_ js.Value, a []js.Value) any {
		v := js.Undefined()
		if len(a) > 0 {
			v = a[0]
		}
		ch <- res{v: v}
		return nil
	})
	catch := js.FuncOf(func(_ js.Value, a []js.Value) any {
		msg := "promise rejected"
		if len(a) > 0 {
			if m := a[0].Get("message"); m.Type() == js.TypeString {
				msg = m.String()
			} else {
				msg = a[0].Call("toString").String()
			}
		}
		ch <- res{err: errors.New(msg)}
		return nil
	})
	defer then.Release()
	defer catch.Release()
	p.Call("then", then, catch)
	r := <-ch
	return r.v, r.err
}

func toU8(b []byte) js.Value {
	a := js.Global().Get("Uint8Array").New(len(b))
	if len(b) > 0 {
		js.CopyBytesToJS(a, b)
	}
	return a
}

func fromU8(v js.Value) []byte {
	n := v.Get("length").Int()
	b := make([]byte, n)
	if n > 0 {
		js.CopyBytesToGo(b, v)
	}
	return b
}

// jsSpawn is the ntxhost.SpawnFunc for the browser.
func jsSpawn(ctx context.Context, wasm []byte, mf *transport.Manifest, cfg []byte) (transport.FrameTransport, error) {
	wasmHostMu.Lock()
	impl := wasmHost
	wasmHostMu.Unlock()
	if impl.Type() != js.TypeObject {
		return nil, errors.New("no WebAssembly host registered: load web/wasm/ntx-host.js (it calls NexTalk.transport._registerHost)")
	}
	h, err := awaitJS(impl.Call("instantiate", mf.ID, toU8(wasm), toU8(cfg)))
	if err != nil {
		return nil, fmt.Errorf("transport: wasm instantiate %q: %w", mf.ID, err)
	}
	t := &jsTransport{h: h, mf: mf}
	for _, c := range strings.Split(h.Get("caps").String(), ",") {
		if c = strings.TrimSpace(c); c != "" {
			if !transport.KnownCapabilities[c] {
				t.kill()
				return nil, fmt.Errorf("transport: wasm %q unknown capability %q", mf.ID, c)
			}
			t.caps = append(t.caps, c)
		}
	}
	if len(t.caps) == 0 {
		t.kill()
		return nil, fmt.Errorf("transport: wasm %q declares no capabilities", mf.ID)
	}
	return t, nil
}

// jsTransport adapts a JS ABI-v1 handle to transport.FrameTransport.
type jsTransport struct {
	h  js.Value
	mf *transport.Manifest

	mu      sync.Mutex
	started bool
	caps    []string
}

// call invokes a handle method, turning a JS exception into an error
// instead of a Go panic.
func (t *jsTransport) call(name string, args ...any) (v js.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("transport: wasm %q %s: %v", t.mf.ID, name, r)
		}
	}()
	return t.h.Call(name, args...), nil
}

func (t *jsTransport) callRC(name string, args ...any) (int, error) {
	v, err := t.call(name, args...)
	if err != nil {
		return 0, err
	}
	return v.Int(), nil
}

func (t *jsTransport) kill() { _, _ = t.call("destroy") }

// Kill force-terminates the instance (ntxhost stopLive).
func (t *jsTransport) Kill() error { t.kill(); return nil }

func (t *jsTransport) ID() string { return t.mf.ID }

func (t *jsTransport) Capabilities() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.caps...)
}

func (t *jsTransport) requireStarted() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started {
		return &transport.RPCError{Code: transport.ErrNotReady, Detail: "transport not started"}
	}
	return nil
}

func (t *jsTransport) Start(ctx context.Context) error {
	rc, err := t.callRC("start")
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("transport: wasm %q start refused: %d", t.mf.ID, rc)
	}
	t.mu.Lock()
	t.started = true
	t.mu.Unlock()
	return nil
}

func (t *jsTransport) Stop(ctx context.Context) error {
	rc, err := t.callRC("stop")
	t.mu.Lock()
	t.started = false
	t.mu.Unlock()
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("transport: wasm %q stop refused: %d", t.mf.ID, rc)
	}
	return nil
}

func (t *jsTransport) SendFrame(ctx context.Context, frame transport.Frame, to transport.RouteHint) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	if len(frame) == 0 || len(frame) > transport.MaxFrameBytes || len(to.RecipientPub) > 64 || len(to.SenderHint) > 64 {
		return &transport.RPCError{Code: transport.ErrInvalid, Detail: "frame out of bounds"}
	}
	rc, err := t.callRC("send", toU8(frame), toU8(to.RecipientPub))
	if err != nil {
		return err
	}
	return ntxhost.ABIError("send", rc)
}

func (t *jsTransport) AttachMailbox(ctx context.Context, mailboxID, readSecret []byte, shardURL, routerURL string) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	if len(mailboxID) != 16 || len(readSecret) != 32 {
		return &transport.RPCError{Code: transport.ErrInvalid, Detail: "bad attach"}
	}
	// ABI v1 queue transports ignore shard/router URLs (same as wazero host).
	rc, err := t.callRC("attach", toU8(mailboxID), toU8(readSecret))
	if err != nil {
		return err
	}
	return ntxhost.ABIError("attach", rc)
}

func (t *jsTransport) DetachMailbox(ctx context.Context, mailboxID []byte) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	if len(mailboxID) != 16 {
		return &transport.RPCError{Code: transport.ErrInvalid, Detail: "bad detach"}
	}
	rc, err := t.callRC("detach", toU8(mailboxID))
	if err != nil {
		return err
	}
	return ntxhost.ABIError("detach", rc)
}

func (t *jsTransport) PollFrames(ctx context.Context, limit int, mailboxID []byte) ([][]byte, error) {
	if err := t.requireStarted(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	var mb any = js.Null()
	if len(mailboxID) == 16 {
		mb = toU8(mailboxID)
	}
	v, err := t.call("poll", limit, mb)
	if err != nil {
		return nil, err
	}
	blob := fromU8(v)
	if len(blob) > ntxhost.MaxPollBlob {
		return nil, fmt.Errorf("transport: wasm poll: blob too large (%d)", len(blob))
	}
	return ntxhost.ParsePollBlob(blob)
}

func (t *jsTransport) Status(ctx context.Context) (bool, string, error) {
	rc, err := t.callRC("status")
	if err != nil {
		return false, "", err
	}
	return rc == 1, "wasm (browser WebAssembly)", nil
}
