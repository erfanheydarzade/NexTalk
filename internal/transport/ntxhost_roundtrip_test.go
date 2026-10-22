//go:build !js

package transport_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/ntxhost"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// External test package: it may import internal/ntxhost (which imports
// transport) without a cycle, and reaches the hand-assembled queue module
// through the BuildQueueModule shim in export_test.go.

type fakeRouter struct{}

func (fakeRouter) Register(context.Context, string, ed25519.PrivateKey) (ntxhost.Capability, error) {
	return ntxhost.Capability{
		MailboxID:  "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
		ReadSecret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		ShardURL:   "https://shard.test",
	}, nil
}
func (fakeRouter) Resolve(context.Context, string, string) (ntxhost.Resolution, error) {
	return ntxhost.Resolution{}, nil
}

func newID(t *testing.T) *client.Client {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dp, dpub := crypto.GenerateDilithiumKeyPair()
	return client.NewClientFromKeys(crypto.DerivePeerID(pub, dpub), priv, pub, dp, dpub, map[string]*crypto.SecurePeer{})
}

func wazeroSpawn(ctx context.Context, wasm []byte, mf *transport.Manifest, cfg []byte) (transport.FrameTransport, error) {
	t, err := transport.NewWASMTransport(ctx, wasm, mf, cfg)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// TestHostInstallEnableRegisterSendPoll is the acceptance round trip on the
// REAL hand-assembled WASM module under wazero: install -> enable ->
// register -> send -> poll (through internal/dispatch).
func TestHostInstallEnableRegisterSendPoll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("manifest.json")
	_, _ = w.Write([]byte(`{"id":"wasm-queue","name":"Wasm Queue","version":"0.0.1","api_version":"1","entry":"queue.wasm","capabilities":["message"],"permissions":[]}`))
	w, _ = zw.Create("queue.wasm")
	_, _ = w.Write(realExtensionWasm(t))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	ntx := buf.Bytes()

	a, b := newID(t), newID(t)
	offer, err := a.CreateOffer(b.Id)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := b.AcceptOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.FinishHandshake(answer); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	cur := a
	ident := func() (*ntxhost.Identity, error) {
		mu.Lock()
		defer mu.Unlock()
		return &ntxhost.Identity{Client: cur, Deps: &dispatch.Deps{Client: cur}}, nil
	}
	h := ntxhost.New(ntxhost.Options{Spawn: wazeroSpawn, Identity: ident, Registrar: fakeRouter{}})

	pkg, err := ntxhost.Inspect(ntx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.Install(ntx, false)
	if err != nil || info.Enabled || info.Hash != pkg.Hash {
		t.Fatalf("install (disabled by default): %+v %v", info, err)
	}
	if err := h.Enable("wasm-queue"); err != nil {
		t.Fatal(err)
	}
	reg, err := h.Register(ctx, "wasm-queue", "https://router.test")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove(ctx, "wasm-queue")
	if running, _, _ := h.Status(ctx, "wasm-queue"); !running {
		t.Fatal("register must have started the WASM runtime")
	}

	if err := h.SendMessage(ctx, "wasm-queue", b.Id, []byte("hi from A via wasm"), ntxhost.SendOptions{}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	cur = b
	mu.Unlock()
	evs, err := h.Poll(ctx, "wasm-queue", ntxhost.PollParams{Mailbox: reg.MailboxID})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Type != "message" || evs[0].Sender != a.Id || evs[0].Message != "hi from A via wasm" {
		t.Fatalf("unexpected events: %+v", evs)
	}
}
