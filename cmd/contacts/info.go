// cmd/contacts/info.go
package contacts

import (
	"github.com/spf13/cobra"
)

func (c *Command) infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <name>",
		Short: "Show details for a single contacts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			s, err := c.store()
			if err != nil {
				return err
			}

			contact, err := s.Get(name)
			if err != nil {
				return err
			}

			type infoOutput struct {
				Name   string `json:"name"`
				UserID string `json:"user_id"`
				Note   string `json:"note,omitempty"`
			}

			return c.printJSON(infoOutput{
				Name:   contact.Name,
				UserID: contact.UserID,
				Note:   contact.Note,
			})
		},
	}
}
