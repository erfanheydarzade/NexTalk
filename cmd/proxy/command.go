package proxy

import (
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/spf13/cobra"
)

type proxyCmd struct {
	engine *core.Engine
	cfg    config.Config
}

func Register(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Proxy relay mode (manual transport)",
	}

	pc := &proxyCmd{
		engine: engine,
		cfg:    cfg,
	}

	cmd.AddCommand(
		pc.runCmd(),
	)

	parent.AddCommand(cmd)
}

func (pc *proxyCmd) runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start proxy runtime",
		Run: func(cmd *cobra.Command, args []string) {
			RunWorker(pc.engine, pc.cfg)
		},
	}
}
