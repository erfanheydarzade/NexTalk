//go:build js && wasm

package wasmbridge

import "syscall/js"

// buildVersion is overridable at build time via:
//
//	go build -ldflags "-X github.com/erfanheydarzade/NexTalk/internal/wasmbridge.buildVersion=v1.2.3"
//
// cmd/nextalk-wasm/build.sh can pass this the same way a release pipeline
// would tag the CLI binaries; it defaults to "dev" for local builds.
var buildVersion = "dev"

// jsVersion() -> { version, api }
// "api" is this package's JS-surface revision, bumped whenever a
// namespace is added/removed/renamed on the NexTalk global — lets JS
// feature-detect against something more precise than "does this key
// exist" for every single call.
func jsVersion(this js.Value, args []js.Value) any {
	return ok(map[string]any{"version": buildVersion, "api": "2"})
}
