//go:build js && wasm

// Command nextalk-wasm compiles NexTalk's crypto/handshake core, plus an
// optional live connection to the same Router/shard relay the CLI's
// `nextalk worker` transport uses, to WebAssembly and exposes it to
// JavaScript under the global `NexTalk` object.
//
// All of the actual logic lives in internal/wasmbridge, split by concern
// (identity / handshake / message / relay / encoding) instead of one
// large file — see that package's doc comment for the layout. This file
// is deliberately just wiring: build tag, call Register(), block forever.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o nextalk.wasm ./cmd/nextalk-wasm
//
// See docs/wasm.md for the JS-side API and usage examples.
package main

import "github.com/erfanheydarzade/NexTalk/internal/wasmbridge"

func main() {
	wasmbridge.Register()

	// Keep the wasm module alive; all real work happens in the
	// js.FuncOf callbacks registered above, invoked from JS.
	select {}
}
