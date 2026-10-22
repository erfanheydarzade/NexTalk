//go:build js && wasm

// NexTalk.transport.* — runtime (extension) transports in the browser.
//
// Every protocol decision lives in internal/ntxhost (tag-free, tested
// natively); this file only converts js.Value <-> Go and decides which
// calls must be Promises. Rule: anything that can do network I/O, start a
// runtime (WebAssembly.instantiate is async) or otherwise block goes
// through async(guard(...)); a synchronous js.FuncOf that waits on fetch
// or a promise deadlocks the Go runtime (the context.sendMulti bug).
//
//	sync : inspect install list enable disable remove status detach
//	       export import _registerHost
//	async: register attach resolve poll sendMessage   (+ xfer.send/receive)
//
// The API has no field for private keys. Bearers (read_secret) cross the
// boundary only in register's result, attach's argument and export().
package wasmbridge

import (
	"context"
	"errors"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/ntxhost"
)

var host = ntxhost.New(ntxhost.Options{Spawn: jsSpawn, Identity: bridgeIdentity})

// bridgeIdentity hands ntxhost the active identity for ONE call. It is
// re-evaluated per call so importIdentity()/init() swaps are picked up.
func bridgeIdentity() (*ntxhost.Identity, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.ActiveClient == nil || st.Id == "" {
		return nil, errors.New("no identity loaded — call NexTalk.init() first")
	}
	return &ntxhost.Identity{Client: st.ActiveClient, Deps: dispatchDepsLocked(), Lock: &dispatchMu}, nil
}

func mountTransport(ns js.Value) {
	obj := func() js.Value { return js.Global().Get("Object").New() }

	t := obj()
	t.Set("inspect", js.FuncOf(guard(jsTransportInspect)))
	t.Set("install", js.FuncOf(guard(jsTransportInstall)))
	t.Set("list", js.FuncOf(guard(jsTransportList)))
	t.Set("enable", js.FuncOf(guard(jsTransportEnable)))
	t.Set("disable", js.FuncOf(guard(jsTransportDisable)))
	t.Set("remove", js.FuncOf(guard(jsTransportRemove)))
	t.Set("status", js.FuncOf(guard(jsTransportStatus)))
	t.Set("register", js.FuncOf(async(guard(jsTransportRegister))))
	t.Set("attach", js.FuncOf(async(guard(jsTransportAttach))))
	t.Set("detach", js.FuncOf(guard(jsTransportDetach)))
	t.Set("resolve", js.FuncOf(async(guard(jsTransportResolve))))
	t.Set("poll", js.FuncOf(async(guard(jsTransportPoll))))
	t.Set("sendMessage", js.FuncOf(async(guard(jsTransportSendMessage))))
	t.Set("export", js.FuncOf(guard(jsTransportExport)))
	t.Set("import", js.FuncOf(guard(jsTransportImport)))
	t.Set("_registerHost", js.FuncOf(guard(jsRegisterHost)))
	ns.Set("transport", t)

	x := obj()
	x.Set("send", js.FuncOf(async(guard(jsXferSend))))
	x.Set("receive", js.FuncOf(async(guard(jsXferReceive))))
	ns.Set("xfer", x)

	tk := obj()
	tk.Set("describe", js.FuncOf(guard(jsTicketDescribe)))
	ns.Set("ticket", tk)
}

// ── small arg helpers ──────────────────────────────────────────────────────

func objStr(v js.Value, key string) string {
	if v.Type() != js.TypeObject {
		return ""
	}
	x := v.Get(key)
	if x.IsUndefined() || x.IsNull() {
		return ""
	}
	return x.String()
}

func objInt(v js.Value, key string) int {
	if v.Type() != js.TypeObject {
		return 0
	}
	if x := v.Get(key); x.Type() == js.TypeNumber {
		return x.Int()
	}
	return 0
}

func argObj(args []js.Value, i int) js.Value {
	if i < len(args) {
		return args[i]
	}
	return js.Undefined()
}

func needID(args []js.Value) (string, js.Value) {
	id := argStr(args, 0)
	if id == "" {
		return "", failStr("missing transport id")
	}
	return id, js.Undefined()
}

// ── sync ───────────────────────────────────────────────────────────────────

// inspect(ntxB64) -> { id, name, version, capabilities, permissions, description, hash, entry }
// Parses only: no install, no state change.
func jsTransportInspect(this js.Value, args []js.Value) any {
	raw, err := b64d(argStr(args, 0))
	if err != nil {
		return fail(err)
	}
	pkg, err := ntxhost.Inspect(raw)
	if err != nil {
		return fail(err)
	}
	m := pkg.Manifest
	caps, perms := m.Capabilities, m.Permissions
	if caps == nil {
		caps = []string{}
	}
	if perms == nil {
		perms = []string{}
	}
	return ok(map[string]any{"id": m.ID, "name": m.Name, "version": m.Version, "capabilities": caps,
		"permissions": perms, "description": m.Description, "hash": pkg.Hash, "entry": m.Entry})
}

// install(ntxB64, enable?) -> { id, hash }   (disabled unless enable === true)
func jsTransportInstall(this js.Value, args []js.Value) any {
	raw, err := b64d(argStr(args, 0))
	if err != nil {
		return fail(err)
	}
	enable := len(args) > 1 && args[1].Type() == js.TypeBoolean && args[1].Bool()
	info, err := host.Install(raw, enable)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"id": info.ID, "hash": info.Hash})
}

// list() -> { transports: [{ id, name, version, enabled, capabilities, permissions, description, hash }] }
func jsTransportList(this js.Value, args []js.Value) any {
	return ok(map[string]any{"transports": host.List()})
}

func jsTransportEnable(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	if err := host.Enable(id); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

func jsTransportDisable(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	if err := host.Disable(context.Background(), id); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

func jsTransportRemove(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	if err := host.Remove(context.Background(), id); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// status(id) -> { running, detail }   (never starts the runtime)
func jsTransportStatus(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	running, detail, err := host.Status(context.Background(), id)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"running": running, "detail": detail})
}

// detach(id, mailbox) -> { ok }
func jsTransportDetach(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	if err := host.Detach(context.Background(), id, argStr(args, 1)); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// export() -> JSON string. Contains read_secret bearers: store it encrypted.
func jsTransportExport(this js.Value, args []js.Value) any {
	s, err := host.Export()
	if err != nil {
		return fail(err)
	}
	return s
}

// import(json) -> { ok }. All-or-nothing; every hash is re-verified.
func jsTransportImport(this js.Value, args []js.Value) any {
	if err := host.Import(context.Background(), argStr(args, 0)); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// ── async ──────────────────────────────────────────────────────────────────

// register(id, { router }) -> { mailbox_id, read_secret, shard_url, router_url }
func jsTransportRegister(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	reg, err := host.Register(context.Background(), id, objStr(argObj(args, 1), "router"))
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"mailbox_id": reg.MailboxID, "read_secret": reg.ReadSecret,
		"shard_url": reg.ShardURL, "router_url": reg.RouterURL})
}

// attach(id, { mailbox, secret, shard, router }) -> { ok }
func jsTransportAttach(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	o := argObj(args, 1)
	err := host.Attach(context.Background(), id, ntxhost.AttachParams{
		Mailbox: objStr(o, "mailbox"), Secret: objStr(o, "secret"),
		Shard: objStr(o, "shard"), Router: objStr(o, "router"),
	})
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// resolve(id, { to, router }) -> { mailbox_id, shard_url }
func jsTransportResolve(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	o := argObj(args, 1)
	mb, shard, err := host.Resolve(context.Background(), id, objStr(o, "to"), objStr(o, "router"))
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"mailbox_id": mb, "shard_url": shard})
}

// poll(id, { mailbox?, limit? }) -> { events: [...] }
// Events come from internal/dispatch: the same shapes (and dedupe) as
// NexTalk.relay.listen(), so one page handler serves both.
func jsTransportPoll(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	o := argObj(args, 1)
	evs, err := host.Poll(context.Background(), id, ntxhost.PollParams{Mailbox: objStr(o, "mailbox"), Limit: objInt(o, "limit")})
	if err != nil {
		return fail(err)
	}
	out := make([]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, e)
	}
	return ok(map[string]any{"events": out})
}

// sendMessage(id, peer, text | { bytes: base64 }, { mailbox?, shard? }) -> { ok }
func jsTransportSendMessage(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	msg, err := messageBytes(args, 2)
	if err != nil {
		return fail(err)
	}
	o := argObj(args, 3)
	if err := host.SendMessage(context.Background(), id, argStr(args, 1), msg,
		ntxhost.SendOptions{Mailbox: objStr(o, "mailbox"), Shard: objStr(o, "shard")}); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}
