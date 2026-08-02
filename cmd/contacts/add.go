// cmd/contacts/add.go
package contacts

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (c *Command) addCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <name> <userid>",
		Short: "Add a contacts alias for a peer ID",
		Example: `  nextalk contacts add alice 5Ht3...
  # Later you can use "alice" wherever a peer ID is expected.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, userID := args[0], args[1]

			s, err := c.store()
			if err != nil {
				return err
			}

			if err := s.Add(name, userID); err != nil {
				return err
			}

			fmt.Printf("Contact %q added → %s\n", name, userID)
			return c.saveAndPrint(s, map[string]string{
				"name":    name,
				"user_id": userID,
			})
		},
	}
}
