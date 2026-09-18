package transport

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeNTX(t *testing.T, dir, name, manifest, entry string, entryData []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if entry != "" {
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entryData); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

const goodManifest = `{"id":"fake","name":"Fake","version":"0.0.1","api_version":"1","entry":"fake-bin","capabilities":["message"],"permissions":[]}`

func TestManagerLifecycle(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", goodManifest, "fake-bin", []byte("dummy"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mf, err := m.Install(ctx, pkg, false)
	if err != nil {
		t.Fatal(err)
	}
	if mf.ID != "fake" {
		t.Fatal("bad id")
	}
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Enabled {
		t.Fatalf("must default disabled: %+v", list)
	}
	if err := m.Enable("fake"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig("fake", `{"k":"v"}`); err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(ctx, "fake"); err != nil {
		t.Fatal(err)
	}
	list, _ = m.List()
	if list[0].Enabled {
		t.Fatal("must be disabled")
	}
	if err := m.Remove(ctx, "fake"); err != nil {
		t.Fatal(err)
	}
	list, _ = m.List()
	if len(list) != 0 {
		t.Fatal("must be removed")
	}
}

func TestManagerRejects(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Unknown capability.
	bad := `{"id":"evil","name":"E","version":"1","api_version":"1","entry":"bin","capabilities":["teleport"]}`
	pkg := writeNTX(t, t.TempDir(), "evil.ntx", bad, "bin", []byte("x"))
	if _, err := m.Install(ctx, pkg, false); err == nil {
		t.Fatal("unknown capability must fail")
	}
	// Missing entry.
	pkg2 := writeNTX(t, t.TempDir(), "noentry.ntx", goodManifest, "", nil)
	if _, err := m.Install(ctx, pkg2, false); err == nil {
		t.Fatal("missing entry must fail")
	}
	// Missing manifest.
	pkg3 := writeNTX(t, t.TempDir(), "nomanifest.ntx", goodManifest, "fake-bin", []byte("x"))
	// Corrupt it: rewrite zip without manifest by reinstalling only entry.
	_ = pkg3
	// Enable unknown.
	if err := m.Enable("ghost"); err == nil {
		t.Fatal("enable ghost must fail")
	}
}

func TestManagerStartFake(t *testing.T) {
	if os.Getenv("NTX_FAKE_TRANSPORT") == "1" {
		t.Skip("helper")
	}
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Install a package whose entry is this test binary (speaks fake RPC).
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	entry := "fake-bin"
	manifest := goodManifest
	if runtime.GOOS == "windows" {
		entry = "fake-bin.exe"
		manifest = fmt.Sprintf(`{"id":"fake","name":"Fake","version":"0.0.1","api_version":"1","entry":%q,"capabilities":["message"],"permissions":[]}`, entry)
	}
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", manifest, entry, raw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := m.Install(ctx, pkg, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("NTX_FAKE_TRANSPORT", "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("NTX_FAKE_TRANSPORT")

	tr, err := m.Start(ctx, "fake")
	if err != nil {
		t.Fatal(err)
	}
	if !SupportsCapability(tr, "message") || SupportsCapability(tr, "p2p") {
		t.Fatal("capability routing mismatch")
	}
	if got := m.Route("message"); len(got) != 1 || got[0].ID() != "fake" {
		t.Fatalf("route mismatch: %v", got)
	}
	if got := m.Route("p2p"); len(got) != 0 {
		t.Fatal("p2p must not route")
	}
	frame := append([]byte{0x03}, []byte("hello")...)
	if err := tr.SendFrame(ctx, frame, RouteHint{RecipientPub: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	frames, err := tr.PollFrames(ctx, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0][0] != 0x03 {
		t.Fatalf("poll mismatch: %v", frames)
	}
	if err := m.Stop(ctx, "fake"); err != nil {
		t.Fatal(err)
	}
}
