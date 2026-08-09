// cmd/root.go
package cmd

import (
	"fmt"

	cmdcontact "github.com/erfanheydarzade/NexTalk/cmd/contacts"
	cmdgui "github.com/erfanheydarzade/NexTalk/cmd/shell"
	_ "github.com/erfanheydarzade/NexTalk/cmd/transports" // triggers all transport init()s
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/buildinfo"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "nextalk",
	Short:   "NexTalk CLI",
	Version: buildinfo.Version,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the nextalk build version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(buildinfo.String())
	},
}

func Execute() error {
	// Cobra's default behavior on Windows is to detect when the binary was
	// double-clicked from Explorer and print its own "This is a command
	// line tool..." splash before exiting — this runs *before* rootCmd.Run
	// ever gets a chance to fire. We want double-clicking to fall through
	// to our own shell instead, so disable that built-in splash.
	cobra.MousetrapHelpText = ""
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

	rootCmd.AddCommand(versionCmd)

	// No subcommand given (e.g. the exe was double-clicked from Explorer
	// instead of run via `nextalk shell`) -> just launch the interactive
	// shell instead of printing help and exiting immediately.
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		cmdgui.RunGUI(engine, cfg)
	}
}
