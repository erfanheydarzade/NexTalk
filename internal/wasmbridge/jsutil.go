//go:build js && wasm

package wasmbridge

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"syscall/js"
)

// ── generic JS <-> Go plumbing ─────────────────────────────────────────────
//
// Nothing in this file knows about identities, sessions, or the handshake.
// It exists so every other file in this package can talk to syscall/js in
// one consistent shape: every exported call returns either a plain object
// or { error: "..." } for JS to check.

func ok(v map[string]any) js.Value {
	b, _ := json.Marshal(v)
	return jsParse(string(b))
}

func fail(err error) js.Value {
	return ok(map[string]any{"error": err.Error()})
}

func failStr(msg string) js.Value {
	return ok(map[string]any{"error": msg})
}

func jsParse(s string) js.Value {
	return js.Global().Get("JSON").Call("parse", s)
}

func argStr(args []js.Value, i int) string {
	if i >= len(args) || args[i].IsUndefined() || args[i].IsNull() {
		return ""
	}
	return args[i].String()
}

func b64d(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func b64e(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }

// guard wraps a js.FuncOf callback so an unrecovered Go panic anywhere in
// the call (e.g. crypto/core code that panics on a hard internal error,
// like newPeer's kyber768 keygen panic) turns into a normal
// { error: "..." } result instead of crashing the whole wasm program.
//
// Without this, a single panic in ANY exported call permanently kills the
// Go runtime (main's `select {}` unwinds), so every call after it — even
// in a different tab, even completely unrelated ones — returns undefined
// to JS and any in-flight promise rejects with "Go program has already
// exited". Every function registered in register.go MUST go through this.
func guard(fn func(this js.Value, args []js.Value) any) func(this js.Value, args []js.Value) any {
	return func(this js.Value, args []js.Value) (result any) {
		defer func() {
			if r := recover(); r != nil {
				result = fail(fmt.Errorf("internal error: %v", r))
			}
		}()
		return fn(this, args)
	}
}

// async wraps a potentially blocking/exported JS call in a Promise so wasm
// network work (for example net/http -> browser fetch) does not run inline on
// the js.FuncOf stack. That avoids the runtime getting torn down while JS is
// still awaiting a result.
func async(fn func(this js.Value, args []js.Value) any) func(this js.Value, args []js.Value) any {
	return func(this js.Value, args []js.Value) any {
		executor := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				defer func() {
					if r := recover(); r != nil {
						reject.Invoke(js.Global().Get("Error").New(fmt.Sprintf("internal error: %v", r)))
					}
				}()

				result := fn(this, args)
				if v, ok := result.(js.Value); ok {
					if !v.IsUndefined() && !v.IsNull() {
						errVal := v.Get("error")
						if !errVal.IsUndefined() && !errVal.IsNull() {
							reject.Invoke(js.Global().Get("Error").New(errVal.String()))
							return
						}
					}
				}
				resolve.Invoke(result)
			}()
			return nil
		})

		promise := js.Global().Get("Promise").New(executor)
		executor.Release()
		return promise
	}
}
