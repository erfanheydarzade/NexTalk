package worker

import (
	"time"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	"github.com/spf13/cobra"
)

// requestTimeout bounds how long a single relay round-trip may take.
const requestTimeout = 15 * time.Second

type Command struct {
	engine *core.Engine
	cfg    config.Config

	// testRelay, when non-nil, is returned by relay() instead of building a
	// live worker adapter — used by tests to exercise the full listen path.
	testRelay relay.Relay
}

// Register mounts the worker subcommands onto parent.
func Register(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
	wc := &Command{engine: engine, cfg: cfg}
	group := &cobra.Command{
		Use:   "worker",
		Short: "Use the encrypted worker relay transport",
		RunE: func(cmd *cobra.Command, args []string) error {
			RunWorker(engine, cfg.WorkerURL)
			return nil
		},
	}
	group.AddCommand(
		wc.InitCommand(),
		wc.ConnectCommand(),
		wc.ListenCommand(),
		wc.EncryptCommand(),

		// The group-chat standard surface — identical commands in every
		// transport (`nextalk worker context|send-multi|contexts|mailbox`).
		groupchat.ContextCLI(groupchat.CLIOptions{Relay: wc.relay}),
		groupchat.SendMultiCLI(groupchat.CLIOptions{Relay: wc.relay}),
		groupchat.ContextsCLI(groupchat.CLIOptions{}),
		groupchat.MailboxCLI(groupchat.CLIOptions{}),
	)

	// Every worker subcommand takes -i/--id: offer local identities for
	// flag-value completion (`nextalk worker listen -i <Tab>`).
	for _, sub := range group.Commands() {
		_ = sub.RegisterFlagCompletionFunc("id", completeLocalID)
	}

	parent.AddCommand(group)
}

func (wc *Command) relay() (relay.Relay, error) {
	if wc.testRelay != nil {
		return wc.testRelay, nil
	}
	return workerrelay.New(wc.cfg.WorkerURL)
}
