// cmd/contacts/note.go
package contacts

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (c *Command) noteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "note <name> <text>",
		Short: "Attach or update a note on a contacts",
		Example: `  nextalk contacts note alice "met at conf 2025"
  nextalk contacts note alice ""   # clear the note`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, note := args[0], args[1]

			s, err := c.store()
			if err != nil {
				return err
			}

			if err := s.SetNote(name, note); err != nil {
				return err
			}

			fmt.Printf("Note updated for %q.\n", name)
			return c.saveAndPrint(s, map[string]string{
				"name": name,
				"note": note,
			})
		},
	}
}
