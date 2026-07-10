package offline

import (
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

func (c *Command) InitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize a local peer identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunInit(c.engine)
		},
	}
}

func RunInit(engine *core.Engine) error {
	client := engine.Initialize()
	fmt.Println("\n[Received from init command]")
	response := InitResponse{
		ID: client.Id,
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}
