// cmd/proxy/register.go
package proxy

import (
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	registry.Register(registry.Entry{
		// GUI is nil for now — proxy has no interactive TUI mode yet.
		// Flip this to &ProxyGUITransport{} once it's implemented.
		GUI:       nil,
		CLI:       &proxyCLITransport{},
		MenuOrder: 3,
	})
}

// ── CLI face ──────────────────────────────────────────────────────────────────

type proxyCLITransport struct{}

func (p *proxyCLITransport) RegisterCLI(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
	Register(parent, engine, cfg) // existing package-level Register
}

// ── GUI face (placeholder) ────────────────────────────────────────────────────
// Uncomment and flesh out when ProxyTransport gets an interactive mode.

type ProxyGUITransport struct{}

func (t *ProxyGUITransport) Name() string      { return "proxy" }
func (t *ProxyGUITransport) MenuLabel() string { return "3. Proxy Mode    (Anonymized Routing)" }

func (t *ProxyGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n  \033[1m\033[34m❖ Proxy Mode ❖\033[0m\n\n")
	return nil
}

func (t *ProxyGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
	fmt.Println("  Proxy interactive mode not yet implemented.")
	return false
}

func (t *ProxyGUITransport) Help() {
	fmt.Println("  Proxy interactive mode not yet implemented.")
}
