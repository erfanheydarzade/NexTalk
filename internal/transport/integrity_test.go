package transport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression: verifyHash used to compute a hash and discard it, so a
// tampered entry binary was executed. Start must now refuse it.
func TestStartRefusesTamperedEntry(t *testing.T) {
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", goodManifest, "fake-bin", []byte("original"))
	if _, err := m.Install(ctx, pkg, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.verifyInstalled("fake"); err != nil {
		t.Fatalf("untouched install must verify: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir(), "fake", "fake-bin"), []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = m.Start(ctx, "fake")
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity failure, got %v", err)
	}
}

func TestStartRefusesTamperedManifestAndMissingPin(t *testing.T) {
	m, _ := NewManager(t.TempDir())
	ctx := context.Background()
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", goodManifest, "fake-bin", []byte("x"))
	if _, err := m.Install(ctx, pkg, true); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(m.Dir(), "fake", "manifest.json")
	raw, _ := os.ReadFile(mp)
	os.WriteFile(mp, []byte(strings.Replace(string(raw), "0.0.1", "9.9.9", 1)), 0o644)
	if _, _, err := m.verifyInstalled("fake"); err == nil {
		t.Fatal("manifest tamper not detected")
	}
	os.WriteFile(mp, raw, 0o644)
	delete(m.state.Files, "fake") // legacy install without a pin
	if _, _, err := m.verifyInstalled("fake"); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("missing pin must fail closed, got %v", err)
	}
}

func TestMinimalEnvAndCappedBuffer(t *testing.T) {
	t.Setenv("NEXTALK_SECRET_TEST", "leak")
	for _, e := range minimalEnv() {
		if strings.HasPrefix(e, "NEXTALK_SECRET_TEST") {
			t.Fatal("env leaked to extension")
		}
	}
	c := &cappedBuffer{max: 10}
	n, _ := c.Write([]byte(strings.Repeat("a", 1000)))
	if n != 1000 || len(c.String()) != 10 {
		t.Fatalf("cap broken: n=%d len=%d", n, len(c.String()))
	}
}
