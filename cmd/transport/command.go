// Command implements `nextalk transport ...`: runtime management of external
// transport modules. No transport code is compiled in here — the manager
// discovers installed transports from disk.
//
// Every command below is a thin frontend over internal/transportops, shared
// verbatim with the interactive shell. Output policy: human UI goes to
// stderr, machine JSON (--json) to stdout.
package transport

import (
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/transportops"
	"github.com/spf13/cobra"
)

// Register mounts the transport group onto parent.
func Register(parent *cobra.Command, _ *core.Engine, _ config.Config) {
	group := &cobra.Command{
		Use:   "transport",
		Short: "Manage runtime transport modules",
	}
	group.AddCommand(
		listCommand(),
		installCommand(),
		removeCommand(),
		enableCommand(),
		disableCommand(),
		statusCommand(),
		configCommand(),
		pollCommand(),
		sendFrameCommand(),
		attachCommand(),
		detachCommand(),
		identityRegisterCommand(),
		registerCommand(),
		resolveCommand(),
		xferSendCommand(),
		xferRecvCommand(),
		xferResumeCommand(),
		xferCancelCommand(),
		xferInspectCommand(),
	)
	parent.AddCommand(group)
}

func openDeps(cmd *cobra.Command) *transportops.Deps {
	dir, _ := cmd.Flags().GetString("transports-dir")
	jsonMode, _ := cmd.Flags().GetBool("json")
	showSecrets, _ := cmd.Flags().GetBool("show-secrets")
	return &transportops.Deps{
		TransportsDir: dir,
		Stdout:        cmd.OutOrStdout(),
		Stderr:        cmd.ErrOrStderr(),
		JSON:          jsonMode,
		ShowSecrets:   showSecrets,
	}
}

func withDir(c *cobra.Command) {
	c.Flags().String("transports-dir", "", "transports directory (default: user config)")
}

// withJSON adds the machine-output and secret-visibility flags.
func withJSON(c *cobra.Command) {
	c.Flags().Bool("json", false, "machine-readable JSON on stdout")
	c.Flags().Bool("show-secrets", false, "print secret values verbatim (redacted otherwise)")
}

func listCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List installed transports",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := transportops.List(openDeps(cmd))
			return err
		},
	}
	withDir(c)
	withJSON(c)
	return c
}

func installCommand() *cobra.Command {
	var enable bool
	c := &cobra.Command{
		Use:   "install <package.ntx>",
		Short: "Install a transport package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.Install(openDeps(cmd), args[0], enable)
		},
	}
	c.Flags().BoolVar(&enable, "enable", false, "enable immediately after install")
	withDir(c)
	withJSON(c)
	return c
}

func removeCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove an installed transport",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.Remove(openDeps(cmd), args[0])
		},
	}
	withDir(c)
	withJSON(c)
	return c
}

func enableCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "enable <id>",
		Short: "Enable an installed transport",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.Enable(openDeps(cmd), args[0])
		},
	}
	withDir(c)
	withJSON(c)
	return c
}

func disableCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "disable <id>",
		Short: "Disable a transport (stops it if running)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.Disable(openDeps(cmd), args[0])
		},
	}
	withDir(c)
	withJSON(c)
	return c
}

func statusCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "status [<id>]",
		Short: "Show transport status",
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			return transportops.Status(openDeps(cmd), id)
		},
	}
	withDir(c)
	withJSON(c)
	return c
}

func configCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "config <id> <json>",
		Short: "Store an opaque config blob passed to the transport at start",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return transportops.SetConfig(openDeps(cmd), args[0], args[1])
		},
	}
	withDir(c)
	withJSON(c)
	return c
}
