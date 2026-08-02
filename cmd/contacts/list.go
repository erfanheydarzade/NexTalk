// cmd/contacts/list.go
package contacts

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

func (c *Command) listCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all contacts in the global contacts book",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := c.store()
			if err != nil {
				return err
			}

			if len(s.Contacts) == 0 {
				fmt.Println("No contacts yet. Use `contacts add <name> <userid>` to add one.")
				return nil
			}

			// Sort by name for deterministic output.
			names := make([]string, 0, len(s.Contacts))
			for name := range s.Contacts {
				names = append(names, name)
			}
			sort.Strings(names)

			type row struct {
				Name   string `json:"name"`
				UserID string `json:"user_id"`
				Note   string `json:"note,omitempty"`
			}

			rows := make([]row, 0, len(names))
			for _, name := range names {
				ct := s.Contacts[name]
				rows = append(rows, row{
					Name:   ct.Name,
					UserID: ct.UserID,
					Note:   ct.Note,
				})
			}

			// Also print a human-readable table to stdout.
			fmt.Printf("%-20s  %-64s  %s\n", "NAME", "USER ID", "NOTE")
			fmt.Printf("%-20s  %-64s  %s\n", "────────────────────", "────────────────────────────────────────────────────────────────", "────────────────────")
			for _, r := range rows {
				shortID := r.UserID
				if len(shortID) > 20 {
					shortID = shortID[:8] + "…" + shortID[len(shortID)-6:]
				}
				fmt.Printf("%-20s  %-64s  %s\n", r.Name, shortID, r.Note)
			}
			fmt.Println()

			return nil
		},
	}
}
