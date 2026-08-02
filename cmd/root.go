// cmd/root.go
package cmd

import (
	cmdcontact "github.com/erfanheydarzade/NexTalk/cmd/contacts"
	cmdgui "github.com/erfanheydarzade/NexTalk/cmd/shell"
	_ "github.com/erfanheydarzade/NexTalk/cmd/transports" // triggers all transport init()s
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nextalk",
	Short: "NexTalk CLI",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	_ = godotenv.Load()

	cfg := config.Load()
	engine := core.NewEngine()

	for _, entry := range registry.CLITransports() {
		entry.CLI.RegisterCLI(rootCmd, engine, cfg)
	}

	cmdgui.Register(rootCmd, engine)

	// Contacts are a global address book (internal/contacts), independent of
	// any client profile, so registering them needs no engine/active client.
	cmdcontact.Register(rootCmd)
}
