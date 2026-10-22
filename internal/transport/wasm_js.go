//go:build js

package transport

import (
	"context"
	"errors"
)

// ErrWASMRuntimeUnavailable is returned by NewWASMTransport in GOOS=js
// builds. The wazero runtime (wasm.go) is compiled out there: whether
// wazero's interpreter builds and runs under GOOS=js GOARCH=wasm has not
// been verified, and the browser already has a native WebAssembly engine.
// The wasm bridge therefore implements the same (ptr,len) / ptr<<32|len
// ABI on the JS side (web/wasm/ntx-host.js) and hands Go a FrameTransport
// backed by JS callbacks (internal/wasmbridge/jshost.go).
var ErrWASMRuntimeUnavailable = errors.New("transport: wazero runtime is not built for GOOS=js; the browser build uses the JS WebAssembly host")

// NewWASMTransport is the js-build stub of the wazero-backed constructor.
func NewWASMTransport(ctx context.Context, moduleBytes []byte, m *Manifest, config []byte) (FrameTransport, error) {
	return nil, ErrWASMRuntimeUnavailable
}
