package shell

import (
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/spf13/cobra"
)

func Register(parent *cobra.Command, engine *core.Engine) {
	cfg := config.Load()
	parent.AddCommand(&cobra.Command{
		Use:   "shell",
		Short: "Start NexTalk interactive shell",
		Run: func(cmd *cobra.Command, args []string) {
			RunGUI(engine, cfg)
		},
	})
}
