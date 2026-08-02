package offline

import (
	"fmt"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal"
	"github.com/spf13/cobra"
)

// InitCommand builds the `init` subcommand.
func (c *Command) InitCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a local peer identity",
		// See encrypt.go/decrypt.go: we own all error reporting ourselves,
		// cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunInit(c.engine, format)
			return internal.ReportAndExit(err, format)
		},
	}

	cmd.Flags().StringVar(&format, "format", "human", "Output format: human, json")

	return cmd
}

func RunInit(engine *core.Engine, format string) error {
	if err := internal.ValidateFormat(format); err != nil {
		return err
	}

	cl := Client.NewClient()

	if format == internal.FormatJSON {
		return internal.WriteJSONResponse(InitResponse{ID: cl.Id})
	}

	fmt.Printf("[✓] Identity created\n\nID:\n%s\n", cl.Id)
	return nil
}
