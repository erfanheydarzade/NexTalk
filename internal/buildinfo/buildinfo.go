// Package buildinfo holds version metadata stamped in at build time via
// -ldflags (see .goreleaser.yaml and cmd/nextalk-wasm/build.sh). Every
// value defaults to "dev" so `go build ./...` and `go run` without any
// ldflags still produce a usable, self-describing binary.
package buildinfo

var (
	// Version is the release tag (e.g. "v1.4.0"), or "dev" for a build
	// made outside the release workflow.
	Version = "dev"
	// Commit is the short git commit hash the build was made from.
	Commit = "none"
	// Date is the build timestamp, RFC3339.
	Date = "unknown"
)

// String renders a single-line "version (commit, date)" summary, the same
// shape `nextalk version` and NexTalk.version() (wasm) both print.
func String() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}
