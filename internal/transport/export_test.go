//go:build !js

package transport

// BuildQueueModule exposes the hand-assembled WASM queue module to external
// test packages (transport_test, which can import internal/ntxhost without
// an import cycle).
func BuildQueueModule() []byte { return buildQueueModule() }
