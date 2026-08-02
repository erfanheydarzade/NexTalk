// cmd/contacts/remove.go
package contacts

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (c *Command) removeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Short:   "Remove a contacts by name",
		Aliases: []string{"rm", "delete"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			s, err := c.store()
			if err != nil {
				return err
			}

			if err := s.Remove(name); err != nil {
				return err
			}

			fmt.Printf("Contact %q removed.\n", name)
			return c.saveAndPrint(s, map[string]string{"removed": name})
		},
	}
}
