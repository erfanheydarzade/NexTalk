// cmd/contacts/rename.go
package contacts

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (c *Command) renameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old-name> <new-name>",
		Short: "Rename a contacts",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldName, newName := args[0], args[1]

			s, err := c.store()
			if err != nil {
				return err
			}

			if err := s.Rename(oldName, newName); err != nil {
				return err
			}

			fmt.Printf("Contact renamed: %q → %q\n", oldName, newName)
			return c.saveAndPrint(s, map[string]string{
				"old_name": oldName,
				"new_name": newName,
			})
		},
	}
}
