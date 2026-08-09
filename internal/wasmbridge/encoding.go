//go:build js && wasm

// Exposes crypto's proquint codec (crypto/encoding_proquint.go) to JS, for
// parity with what offline mode can already do — a human-pronounceable
// encoding for showing/reading back a short binary value (e.g. a peer ID
// or a fingerprint) instead of raw base64, useful for out-of-band
// verification ("read me the five words on your screen").
package wasmbridge

import (
	"fmt"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/crypto"
)

// jsToProquint(base64) -> { proquint: "lusab-babad-..." }
func jsToProquint(this js.Value, args []js.Value) any {
	data, err := b64d(argStr(args, 0))
	if err != nil {
		return fail(fmt.Errorf("decode input: %w", err))
	}
	return ok(map[string]any{"proquint": crypto.ToProquint(data)})
}

// jsFromProquint(proquint) -> { data: base64 }
func jsFromProquint(this js.Value, args []js.Value) any {
	data, err := crypto.FromProquint(argStr(args, 0))
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"data": b64e(data)})
}
