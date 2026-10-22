//go:build !js

package transport_test

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// realExtensionWasm returns the relay-example.wasm that the Node toolchain
// (example-transports/build-all.mjs) builds, so the acceptance tests run the
// artifact that actually ships. Skips when node is unavailable.
func realExtensionWasm(t *testing.T) []byte {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "example-transports"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; cannot build the WASM extension")
	}
	cmd := exec.Command("node", "build-all.mjs", "--wasm-only")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build extension: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "dist", "relay-example-wasm.ntx"))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == "relay-example.wasm" {
			rc, _ := f.Open()
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return b
		}
	}
	t.Fatal("relay-example.wasm missing from package")
	return nil
}
