package cmd

import (
	Client "github.com/erfanheydarzade/NexTalk/client"
	cmdgui "github.com/erfanheydarzade/NexTalk/cmd/gui"
	cmdoffline "github.com/erfanheydarzade/NexTalk/cmd/offline"
	cmdproxy "github.com/erfanheydarzade/NexTalk/cmd/proxy"
	cmdworker "github.com/erfanheydarzade/NexTalk/cmd/worker"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
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
	engine := core.NewEngine(&Client.Client{})

	cmdoffline.Register(rootCmd, engine)
	cmdworker.Register(rootCmd, engine, cfg)
	cmdproxy.Register(rootCmd, engine, cfg)
	cmdgui.Register(rootCmd, engine)
}
