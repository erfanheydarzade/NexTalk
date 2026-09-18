package transport

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWASMInstallToRun packages the queue module as .ntx, installs it with
// no rebuild, and runs frames through the manager-selected WASM runtime.
func TestWASMInstallToRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "queue.ntx")
	f, err := os.Create(pkg)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("manifest.json")
	_, _ = w.Write([]byte(`{"id":"wasm-queue","name":"Wasm Queue","version":"0.0.1","api_version":"1","entry":"queue.wasm","capabilities":["message"],"permissions":[]}`))
	w, _ = zw.Create("queue.wasm")
	_, _ = w.Write(buildQueueModule())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	mf, err := m.Install(ctx, pkg, true)
	if err != nil {
		t.Fatal(err)
	}
	if mf.ID != "wasm-queue" {
		t.Fatal("bad id")
	}
	tr, err := m.Start(ctx, "wasm-queue")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop(ctx, "wasm-queue")
	if got := m.Route("message"); len(got) == 0 {
		t.Fatal("wasm transport must route message")
	}
	frame := append([]byte{0x03}, []byte("via-wasm")...)
	if err := tr.SendFrame(ctx, frame, RouteHint{RecipientPub: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	got, err := tr.PollFrames(ctx, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 frame, got %d", len(got))
	}
}
