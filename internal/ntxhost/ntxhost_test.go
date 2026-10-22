package ntxhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

func TestInspectHasNoSideEffectsAndFailsClosed(t *testing.T) {
	h := New(Options{})
	good := makeNTX(t, manifestJSON("q-one", "q.wasm", "message"), "q.wasm", minimalWasm)
	pkg, err := Inspect(good)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Manifest.ID != "q-one" || pkg.Hash != HashBytes(good) {
		t.Fatalf("bad inspect result: %+v", pkg)
	}
	if len(h.List()) != 0 {
		t.Fatal("inspect must not install anything")
	}

	cases := map[string][]byte{
		"unknown capability": makeNTX(t, manifestJSON("x", "x.wasm", "message", "teleport"), "x.wasm", minimalWasm),
		"unknown permission": makeNTX(t, strings.Replace(manifestJSON("x", "x.wasm", "message"), `"permissions":[]`, `"permissions":["root"]`, 1), "x.wasm", minimalWasm),
		"not wasm bytes":     makeNTX(t, manifestJSON("x", "x.wasm", "message"), "x.wasm", []byte("MZ-not-wasm")),
		"not a zip":          []byte("definitely not a zip file"),
	}
	for name, raw := range cases {
		if _, err := Inspect(raw); err == nil {
			t.Errorf("%s: Inspect must fail", name)
		}
	}
}

func TestInstallRejectsProcessEntry(t *testing.T) {
	h := New(Options{})
	raw := makeNTX(t, manifestJSON("proc-t", "bridge", "message"), "bridge", []byte("#!/bin/sh\n"))
	_, err := h.Install(raw, true)
	if err == nil || !strings.Contains(err.Error(), "process model") {
		t.Fatalf("process-entry package must be rejected with a clear error, got %v", err)
	}
	if len(h.List()) != 0 {
		t.Fatal("rejected package must not be installed")
	}
}

func TestInstallDisabledByDefaultThenEnable(t *testing.T) {
	q := &memQueue{}
	h := New(Options{Spawn: memSpawn(q), Identity: (&who{}).fn})
	raw := makeNTX(t, manifestJSON("q-two", "q.wasm", "message"), "q.wasm", minimalWasm)
	info, err := h.Install(raw, false)
	if err != nil || info.Enabled {
		t.Fatalf("install must be disabled by default: %+v %v", info, err)
	}
	if _, _, err := h.ensure(context.Background(), "q-two"); err == nil {
		t.Fatal("disabled transport must not start")
	}
	if err := h.Enable("q-two"); err != nil {
		t.Fatal(err)
	}
	if l := h.List(); len(l) != 1 || !l[0].Enabled || l[0].Hash != HashBytes(raw) {
		t.Fatalf("bad list: %+v", l)
	}
	// Enable re-verifies the pin: corrupt the stored bytes and it must refuse.
	h.mu.Lock()
	h.recs["q-two"].pkg.Raw[len(h.recs["q-two"].pkg.Raw)/2] ^= 0xff
	h.mu.Unlock()
	if err := h.Enable("q-two"); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("enable must re-verify the pinned hash, got %v", err)
	}
	if h.List()[0].Enabled {
		t.Fatal("failed verification must leave the transport disabled")
	}
}

func TestEnsureRefusesUndeclaredCapability(t *testing.T) {
	q := &memQueue{}
	spawn := func(_ context.Context, _ []byte, mf *transport.Manifest, _ []byte) (transport.FrameTransport, error) {
		return &memTransport{id: mf.ID, caps: []string{"message", "binary-transfer"}, q: q}, nil // manifest says message only
	}
	h := New(Options{Spawn: spawn})
	if _, err := h.Install(makeNTX(t, manifestJSON("liar", "l.wasm", "message"), "l.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.ensure(context.Background(), "liar"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("module may not claim more than its manifest, got %v", err)
	}
}

func TestExportImportRoundTripAndTamper(t *testing.T) {
	ctx := context.Background()
	w := &who{}
	a, _ := pair(t)
	w.set(a)
	q := &memQueue{}
	h := New(Options{Spawn: memSpawn(q), Identity: w.fn, Registrar: &fakeRegistrar{}})
	raw := makeNTX(t, manifestJSON("q-exp", "q.wasm", "message"), "q.wasm", minimalWasm)
	if _, err := h.Install(raw, true); err != nil {
		t.Fatal(err)
	}
	reg, err := h.Register(ctx, "q-exp", "https://router.test")
	if err != nil {
		t.Fatal(err)
	}
	exported, err := h.Export()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exported, reg.ReadSecret) {
		t.Fatal("export carries the read_secret bearer (documented); it is missing")
	}
	if strings.Contains(exported, hex.EncodeToString(a.IdentityPrivate)) || strings.Contains(exported, base64.StdEncoding.EncodeToString(a.IdentityPrivate)) {
		t.Fatal("export must never contain identity private keys")
	}

	// Clean import restores package, enabled flag and attachment.
	h2 := New(Options{Spawn: memSpawn(q), Identity: w.fn})
	if err := h2.Import(ctx, exported); err != nil {
		t.Fatal(err)
	}
	l := h2.List()
	if len(l) != 1 || !l[0].Enabled || l[0].ID != "q-exp" {
		t.Fatalf("import did not restore state: %+v", l)
	}
	if len(h2.recs["q-exp"].attach) != 1 {
		t.Fatal("attachment not restored")
	}

	// Tamper 1: a different (valid) package under the recorded hash.
	var doc exportDoc
	if err := json.Unmarshal([]byte(exported), &doc); err != nil {
		t.Fatal(err)
	}
	evil := makeNTX(t, manifestJSON("q-exp", "q.wasm", "message"), "q.wasm", append(append([]byte(nil), minimalWasm...), 0xde, 0xad))
	doc.Transports[0].Package = base64.StdEncoding.EncodeToString(evil)
	bad, _ := json.Marshal(doc)
	h3 := New(Options{Spawn: memSpawn(q), Identity: w.fn})
	if _, err := h3.Install(raw, false); err != nil {
		t.Fatal(err)
	}
	if err := h3.Import(ctx, string(bad)); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered package must fail the hash check on import, got %v", err)
	}
	if len(h3.List()) != 1 {
		t.Fatal("a failed import must leave existing state untouched")
	}

	// Tamper 2: flipped byte inside the package.
	pk, _ := base64.StdEncoding.DecodeString(doc.Transports[0].Package)
	good, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(raw))
	good[len(good)/2] ^= 0x01
	_ = pk
	doc.Transports[0].Package = base64.StdEncoding.EncodeToString(good)
	bad, _ = json.Marshal(doc)
	if err := New(Options{}).Import(ctx, string(bad)); err == nil {
		t.Fatal("bit-flipped package must be rejected on import")
	}

	// Tamper 3: process-model package smuggled in via import.
	proc := makeNTX(t, manifestJSON("q-exp", "bridge", "message"), "bridge", []byte("#!/bin/sh"))
	doc.Transports[0].Package, doc.Transports[0].Hash = base64.StdEncoding.EncodeToString(proc), HashBytes(proc)
	bad, _ = json.Marshal(doc)
	if err := New(Options{}).Import(ctx, string(bad)); err == nil || !strings.Contains(err.Error(), "process model") {
		t.Fatalf("import must also reject process-model packages, got %v", err)
	}
}

func TestMessageRoundTripThroughDispatch(t *testing.T) {
	ctx := context.Background()
	a, b := pair(t)
	w := &who{}
	q := &memQueue{}
	h := New(Options{Spawn: memSpawn(q), Identity: w.fn, Registrar: &fakeRegistrar{}})
	if _, err := h.Install(makeNTX(t, manifestJSON("q-msg", "q.wasm", "message"), "q.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}

	w.set(a)
	reg, err := h.Register(ctx, "q-msg", "https://router.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SendMessage(ctx, "q-msg", b.Id, []byte("hello over transport"), SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.SendMessage(ctx, "q-msg", b.Id, []byte{0xff, 0xfe, 0x00, 0x01}, SendOptions{Mailbox: reg.MailboxID, Shard: reg.ShardURL}); err != nil {
		t.Fatal(err)
	}

	// B polls: A's attachment is owned by A, so B must name the mailbox.
	w.set(b)
	if _, err := h.Poll(ctx, "q-msg", PollParams{}); err == nil {
		t.Fatal("polling must not drain another identity's mailbox implicitly")
	}
	evs, err := h.Poll(ctx, "q-msg", PollParams{Mailbox: reg.MailboxID})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %+v", evs)
	}
	if evs[0].Type != "message" || evs[0].Sender != a.Id || evs[0].Encoding != "utf-8" || evs[0].Message != "hello over transport" {
		t.Fatalf("bad text event: %+v", evs[0])
	}
	if evs[1].Encoding != "base64" || evs[1].Message != base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x00, 0x01}) {
		t.Fatalf("bad binary event: %+v", evs[1])
	}
	// Replaying the same ciphertext is not a new message (ratchet replay protection).
	if evs, _ = h.Poll(ctx, "q-msg", PollParams{Mailbox: reg.MailboxID}); len(evs) != 0 {
		t.Fatalf("queue must be drained, got %+v", evs)
	}
}

func TestHandshakeOverTransportEmitsBrowserEventShape(t *testing.T) {
	ctx := context.Background()
	a, b := newClient(t), newClient(t)
	w := &who{}
	q := &memQueue{}
	h := New(Options{Spawn: memSpawn(q), Identity: w.fn, Registrar: &fakeRegistrar{}})
	if _, err := h.Install(makeNTX(t, manifestJSON("q-hs", "q.wasm", "message"), "q.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}
	w.set(a)
	reg, err := h.Register(ctx, "q-hs", "https://router.test")
	if err != nil {
		t.Fatal(err)
	}
	tr, _, _ := h.ensure(ctx, "q-hs")

	offer, err := a.CreateOffer(b.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.SendFrame(ctx, frame.Wrap(relay.TypeOffer, offer), transport.RouteHint{}); err != nil {
		t.Fatal(err)
	}

	w.set(b)
	evs, err := h.Poll(ctx, "q-hs", PollParams{Mailbox: reg.MailboxID})
	if err != nil || len(evs) != 1 {
		t.Fatalf("poll: %v %+v", err, evs)
	}
	e := evs[0]
	if e.Type != "offer" || e.Peer != a.Id || e.Pubkey != hex.EncodeToString(a.IdentityPublic) ||
		len(e.Actions) != 1 || e.Actions[0].Type != "answer_sent" {
		t.Fatalf("offer event must match the listen() shape the UI parses: %+v", e)
	}
	js, _ := json.Marshal(e)
	for _, k := range []string{`"type":"offer"`, `"peer":`, `"pubkey":`, `"actions":`} {
		if !bytes.Contains(js, []byte(k)) {
			t.Fatalf("event JSON missing %s: %s", k, js)
		}
	}

	// The auto-sent answer went back through the same transport.
	w.set(a)
	evs, err = h.Poll(ctx, "q-hs", PollParams{Mailbox: reg.MailboxID})
	if err != nil || len(evs) != 1 || evs[0].Type != "answer" || evs[0].Peer != b.Id {
		t.Fatalf("answer: %v %+v", err, evs)
	}
	if _, ok := a.Sessions[b.Id]; !ok {
		t.Fatal("session must be established after the answer")
	}
}

func TestResolveAndDetach(t *testing.T) {
	ctx := context.Background()
	a, b := pair(t)
	w := &who{}
	w.set(a)
	h := New(Options{Spawn: memSpawn(&memQueue{}), Identity: w.fn, Registrar: &fakeRegistrar{}})
	if _, err := h.Install(makeNTX(t, manifestJSON("q-r", "q.wasm", "message"), "q.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}
	mb, shard, err := h.Resolve(ctx, "q-r", b.Id, "https://router.test")
	if err != nil || len(mb) != 32 || shard == "" {
		t.Fatalf("resolve: %q %q %v", mb, shard, err)
	}
	reg, err := h.Register(ctx, "q-r", "https://router.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Detach(ctx, "q-r", reg.MailboxID); err != nil {
		t.Fatal(err)
	}
	if err := h.Detach(ctx, "q-r", reg.MailboxID); err == nil {
		t.Fatal("detaching twice must fail")
	}
	if _, _, err := h.Resolve(ctx, "q-r", "not-a-peer", "https://router.test"); err == nil {
		t.Fatal("bad recipient must fail")
	}
}

func TestStatusNeverStartsAndDisableStops(t *testing.T) {
	ctx := context.Background()
	w := &who{}
	w.set(newClient(t))
	h := New(Options{Spawn: memSpawn(&memQueue{}), Identity: w.fn})
	if _, err := h.Install(makeNTX(t, manifestJSON("q-s", "q.wasm", "message"), "q.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}
	if running, _, err := h.Status(ctx, "q-s"); err != nil || running {
		t.Fatalf("status must not start anything: %v %v", running, err)
	}
	tr, _, err := h.ensure(ctx, "q-s")
	if err != nil {
		t.Fatal(err)
	}
	if running, _, _ := h.Status(ctx, "q-s"); !running {
		t.Fatal("must report running after start")
	}
	if err := h.Disable(ctx, "q-s"); err != nil {
		t.Fatal(err)
	}
	if !tr.(*memTransport).killed {
		t.Fatal("disable must kill the runtime")
	}
	if running, detail, _ := h.Status(ctx, "q-s"); running || detail != "disabled" {
		t.Fatalf("after disable: %v %q", running, detail)
	}
	if err := h.Remove(ctx, "q-s"); err != nil || len(h.List()) != 0 {
		t.Fatalf("remove: %v %+v", err, h.List())
	}
}

func TestParsePollBlob(t *testing.T) {
	f1, f2 := []byte{3, 'a'}, []byte{3, 'b', 'c'}
	blob := append(append(append([]byte{0, 0, 0, 2}, f1...), 0, 0, 0, 3), f2...)
	got, err := ParsePollBlob(blob)
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], f1) || !bytes.Equal(got[1], f2) {
		t.Fatalf("parse: %v %v", got, err)
	}
	if got, err := ParsePollBlob(nil); err != nil || len(got) != 0 {
		t.Fatal("empty blob means no frames")
	}
	for name, bad := range map[string][]byte{
		"truncated prefix": {0, 0, 0},
		"zero length":      {0, 0, 0, 0},
		"overrun":          {0, 0, 0, 9, 1},
		"oversize":         {0, 0xff, 0xff, 0xff, 1},
	} {
		if _, err := ParsePollBlob(bad); err == nil {
			t.Errorf("%s must fail", name)
		}
	}
}

func TestABIError(t *testing.T) {
	if ABIError("send", 0) != nil {
		t.Fatal("rc 0 is success")
	}
	for rc, want := range map[int]string{1: "not started", 3: "queue full", 9: "refused: 9"} {
		if err := ABIError("send", rc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("send rc %d: %v", rc, err)
		}
	}
	if err := ABIError("attach", 2); err == nil {
		t.Fatal("attach rc 2 must error")
	}
}
