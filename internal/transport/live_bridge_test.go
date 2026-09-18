package transport

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveInstalledBridge spawns the real installed filerelay bridge (if
// present at NEXTALK_TRANSPORTS_DIR) and runs initialize/caps/status.
// Skipped when absent — this is a live-wiring check, not a unit test.
func TestLiveInstalledBridge(t *testing.T) {
	dir := os.Getenv("NEXTALK_TRANSPORTS_DIR")
	if dir == "" {
		t.Skip("no live transports dir")
	}
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, inst := range list {
		if inst.Manifest.ID == "filerelay" {
			found = true
		}
	}
	if !found {
		t.Skip("filerelay not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := m.Start(ctx, "filerelay")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop(ctx, "filerelay")
	running, detail, err := tr.Status(ctx)
	if err != nil || !running {
		t.Fatalf("bridge status: running=%v detail=%q err=%v", running, detail, err)
	}
	if got := m.Route("message"); len(got) == 0 {
		t.Fatal("filerelay must route message capability")
	}
}
