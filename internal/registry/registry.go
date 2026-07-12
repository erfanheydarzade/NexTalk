// internal/registry/registry.go
//
// Package registry is the single place that knows which transports exist.
// It deliberately knows nothing about any specific transport — transports
// register themselves via their own init() functions, so adding a new one
// never requires editing root.go or shell.go.
package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/spf13/cobra"
)

// ── Interfaces ────────────────────────────────────────────────────────────────

// GUITransport is what the interactive TUI shell calls. Every method receives
// *State instead of individual fields so that the interface stays stable as
// the shared state grows (e.g. adding a Proxy field doesn't change signatures).
type GUITransport interface {
	// Name is the short, lowercase identifier used in the sub-shell prompt,
	// e.g. "worker", "offline", "proxy".
	Name() string

	// MenuLabel is the line printed in the main menu, e.g. "2. Worker Mode".
	MenuLabel() string

	// Init is called once when the user picks this transport from the main menu.
	// It should initialise any transport-specific clients stored in *State and
	// print its own welcome banner. Return a non-nil error to abort the switch.
	Init(state *State) error

	// Execute handles one command line typed inside the transport sub-shell.
	// Return false to leave the sub-shell and return to the main menu.
	Execute(state *State, cmd string, args []string) bool

	// Help prints transport-specific command help.
	Help()
}

// CLITransport is what the cobra root command calls. It mirrors the existing
// per-package Register signatures so transports can implement it with a
// one-liner wrapper.
type CLITransport interface {
	// RegisterCLI mounts the transport's cobra subcommands onto parent.
	RegisterCLI(parent *cobra.Command, engine *core.Engine, cfg config.Config)
}

// Entry bundles both optional faces of a transport. A transport that only
// runs as a CLI command can leave GUI nil; a purely interactive transport
// can leave CLI nil.
type Entry struct {
	// GUI is optional — nil if the transport has no interactive TUI mode.
	GUI GUITransport
	// CLI is optional — nil if the transport has no cobra commands.
	CLI CLITransport
	// MenuOrder controls the position in the main menu (lower = higher up).
	MenuOrder int
}

// ── Global registry ───────────────────────────────────────────────────────────

var (
	mu      sync.RWMutex
	entries []Entry // kept in MenuOrder order after every Register call
)

// Register adds a transport Entry to the global registry. It is safe to call
// from multiple init() functions concurrently. Panics on a duplicate Name()
// so misconfigured binaries fail loudly at startup rather than silently
// dropping a transport.
func Register(e Entry) {
	mu.Lock()
	defer mu.Unlock()

	if e.GUI != nil {
		for _, existing := range entries {
			if existing.GUI != nil && existing.GUI.Name() == e.GUI.Name() {
				panic(fmt.Sprintf("registry: duplicate GUI transport name %q", e.GUI.Name()))
			}
		}
	}

	entries = append(entries, e)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].MenuOrder < entries[j].MenuOrder
	})
}

// GUITransports returns all registered entries that have a GUITransport, in
// MenuOrder. The slice is a copy — callers may not modify the registry through
// it.
func GUITransports() []Entry {
	mu.RLock()
	defer mu.RUnlock()

	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.GUI != nil {
			out = append(out, e)
		}
	}
	return out
}

// CLITransports returns all registered entries that have a CLITransport, in
// MenuOrder.
func CLITransports() []Entry {
	mu.RLock()
	defer mu.RUnlock()

	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.CLI != nil {
			out = append(out, e)
		}
	}
	return out
}
