package offline

import (
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/spf13/cobra"
)

type Command struct {
	engine *core.Engine
}

func Register(parent *cobra.Command, engine *core.Engine) {
	parent.AddCommand(
		New(engine).Root(),
	)
}

func New(engine *core.Engine) *Command {
	return &Command{
		engine: engine,
	}
}

func (c *Command) Root() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "offline",
		Short: "Offline handshake and encrypted messaging tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			RunOffline(c.engine)
			return nil
		},
	}

	cmd.AddCommand(
		c.InitCommand(),
		c.OfferCommand(),
		c.AcceptCommand(),
		c.FinishCommand(),
		c.EncryptCommand(),
		c.DecryptCommand(),
	)

	// The group-chat standard surface — identical in every transport.
	// Offline has no relay, so send-multi exports per-recipient transfer
	// containers instead of transmitting.
	cmd.AddCommand(
		groupchat.ContextCLI(groupchat.CLIOptions{}),
		groupchat.SendMultiCLI(groupchat.CLIOptions{}),
		groupchat.ContextsCLI(groupchat.CLIOptions{}),
		groupchat.MailboxCLI(groupchat.CLIOptions{}),
	)

	return cmd
}
