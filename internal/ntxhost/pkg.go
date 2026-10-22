// Package ntxhost is the portable (no build tags) core behind the browser
// bridge's NexTalk.transport.* / NexTalk.xfer.* surface.
//
// It owns everything that is not syscall/js: parsing and pinning .ntx
// packages, the install/enable/attach registry, export/import, polling
// through internal/dispatch, sending through a FrameTransport, and
// file transfer. Keeping it tag-free means the exact code the browser runs
// is exercised by ordinary `go test` natively; internal/wasmbridge only
// adds thin js.Value glue and a JS-backed FrameTransport on top.
//
// Trust model (unchanged from internal/transport): transports see opaque
// frames, recipient public keys, mailbox bearers and URLs — never private
// keys. Nothing in this package's API accepts or returns key material.
package ntxhost

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// Size ceilings. A browser tab is not a server: keep packages small.
const (
	MaxPackageBytes = 32 << 20
	MaxEntryBytes   = 24 << 20
	maxManifest     = 64 * 1024
)

// Package is a parsed, hash-pinned .ntx (zip with manifest.json + entry).
type Package struct {
	Manifest *transport.Manifest
	Entry    []byte // the .wasm module bytes
	Raw      []byte // the whole package as supplied (what Hash covers)
	Hash     string // lowercase hex sha256(Raw)
}

// HashBytes is the single definition of the package pin.
func HashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Inspect parses a package WITHOUT any side effect. It fails closed:
// unknown capabilities/permissions (transport.ParseManifest), non-.wasm
// entries (process-model transports cannot run in a browser), duplicate zip
// members, oversize members and entries that are not WebAssembly.
func Inspect(raw []byte) (*Package, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("ntxhost: empty package")
	}
	if len(raw) > MaxPackageBytes {
		return nil, fmt.Errorf("ntxhost: package too large (%d bytes, max %d)", len(raw), MaxPackageBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("ntxhost: not a valid .ntx (zip) package: %w", err)
	}
	files := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		if _, dup := files[f.Name]; dup {
			return nil, fmt.Errorf("ntxhost: duplicate member %q in package", f.Name)
		}
		files[f.Name] = f
	}
	mfFile, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("ntxhost: manifest.json missing")
	}
	mfRaw, err := readMember(mfFile, maxManifest)
	if err != nil {
		return nil, fmt.Errorf("ntxhost: manifest.json: %w", err)
	}
	mf, err := transport.ParseManifest(mfRaw)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(strings.ToLower(mf.Entry), ".wasm") {
		return nil, fmt.Errorf("ntxhost: transport %q uses the process model (entry %q): only .wasm entries can run in the browser", mf.ID, mf.Entry)
	}
	entryFile, ok := files[mf.Entry]
	if !ok {
		return nil, fmt.Errorf("ntxhost: entry %q missing from package", mf.Entry)
	}
	entry, err := readMember(entryFile, MaxEntryBytes)
	if err != nil {
		return nil, fmt.Errorf("ntxhost: entry %q: %w", mf.Entry, err)
	}
	if len(entry) < 8 || !bytes.Equal(entry[:4], []byte{0x00, 'a', 's', 'm'}) {
		return nil, fmt.Errorf("ntxhost: entry %q is not a WebAssembly module", mf.Entry)
	}
	return &Package{Manifest: mf, Entry: entry, Raw: append([]byte(nil), raw...), Hash: HashBytes(raw)}, nil
}

// Verify re-hashes the package bytes against a pin.
func (p *Package) Verify(pinned string) error {
	if pinned == "" {
		return fmt.Errorf("ntxhost: %q has no install hash", p.Manifest.ID)
	}
	if got := HashBytes(p.Raw); got != pinned {
		return fmt.Errorf("ntxhost: package hash mismatch for %q (pinned %s…, got %s…)", p.Manifest.ID, short(pinned), short(got))
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func readMember(f *zip.File, max uint64) ([]byte, error) {
	if f.UncompressedSize64 > max {
		return nil, fmt.Errorf("too large (%d bytes, max %d)", f.UncompressedSize64, max)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Never trust the declared size alone (zip bombs): cap the read too.
	b, err := io.ReadAll(io.LimitReader(rc, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > max {
		return nil, fmt.Errorf("too large (max %d bytes)", max)
	}
	return b, nil
}
