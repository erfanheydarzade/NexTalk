package worker

import (
	"time"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	"github.com/spf13/cobra"
)

// requestTimeout bounds how long a single relay round-trip may take.
const requestTimeout = 15 * time.Second

type Command struct {
	engine *core.Engine
	cfg    config.Config
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
	)
	parent.AddCommand(group)
}

func (wc *Command) relay() (relay.Relay, error) {
	return workerrelay.New(wc.cfg.WorkerURL)
}
