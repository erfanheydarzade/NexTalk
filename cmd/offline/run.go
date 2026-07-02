package offline

import "github.com/spf13/cobra"

func (c *Command) RunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the offline runtime",
		RunE: func(cmd *cobra.Command, args []string) error {
			RunOffline(c.engine)
			return nil
		},
	}
}
