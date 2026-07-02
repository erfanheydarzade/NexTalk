package gui

import (
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/spf13/cobra"
)

func Register(parent *cobra.Command, engine *core.Engine) {
	cfg := config.Load()
	cmd := &cobra.Command{
		Use:   "gui",
		Short: "Start NexTalk GUI mode",
		Run: func(cmd *cobra.Command, args []string) {
			RunGUI(engine, cfg)
		},
	}

	parent.AddCommand(cmd)
}
