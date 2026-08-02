// cmd/contacts/command.go
package contacts

import (
	"encoding/json"
	"os"

	"github.com/erfanheydarzade/NexTalk/internal/contacts"
	"github.com/spf13/cobra"
)

// Command bundles state shared by every `contacts` subcommand.
//
// Contacts are a global address book (internal/contacts), independent of
// any client profile — so, unlike cmd/proxy or cmd/worker, this command
// needs no *core.Engine and no loaded client to operate. Each subcommand
// loads the store fresh, mutates it, and saves it back.
type Command struct{}

// Register mounts `nextalk contacts` and its subcommands onto parent.
func Register(parent *cobra.Command) {
	c := &Command{}

	root := &cobra.Command{
		Use:   "contacts",
		Short: "Manage the global contacts book (no active client required)",
	}

	root.AddCommand(
		c.addCmd(),
		c.removeCmd(),
		c.renameCmd(),
		c.noteCmd(),
		c.infoCmd(),
		c.listCmd(),
	)

	parent.AddCommand(root)
}

// ── helpers shared by subcommands ────────────────────────────────────────────

// store loads the global contacts book from disk.
func (c *Command) store() (*contacts.Store, error) {
	return contacts.Load()
}

// saveAndPrint persists the store and prints result as JSON. Use this after
// any mutation (add/remove/rename/note).
func (c *Command) saveAndPrint(s *contacts.Store, payload any) error {
	if err := s.Save(); err != nil {
		return err
	}
	return c.printJSON(payload)
}

// printJSON prints payload as JSON without touching the store file. Use this
// for read-only subcommands (info/list) so they don't rewrite contacts.json.
func (c *Command) printJSON(payload any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
