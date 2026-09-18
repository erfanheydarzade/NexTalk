// Package transport wires the runtime transport manager CLI into NexTalk.
// It is CLI-only: external transports need no GUI face and no rebuild.
package transport

import (
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	registry.Register(registry.Entry{
		CLI:       &transportCLITransport{},
		MenuOrder: 90,
	})
}

type transportCLITransport struct{}

func (t *transportCLITransport) RegisterCLI(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
	Register(parent, engine, cfg)
}
