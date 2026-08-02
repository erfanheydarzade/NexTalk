package worker

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/spf13/cobra"
)

// InitCommand builds the `init` subcommand.
func (c *Command) InitCommand() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize identity and register a mailbox with the worker",
		// We own all error reporting (human vs json) — cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.RunInit(cmd.Context(), format)
			return reportAndExit(err, format)
		},
	}

	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")

	return cmd
}

func (c *Command) RunInit(ctx context.Context, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl := client.NewClient()

	pubHex, err := r.Register(ctx, cl.IdentityPrivate)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	expectedPubHex := hex.EncodeToString(cl.IdentityPublic)
	if expectedPubHex != pubHex {
		return fmt.Errorf(
			"identity mismatch: local=%s worker=%s",
			expectedPubHex,
			pubHex,
		)
	}

	response := InitResponse{ID: cl.Id}

	if format == formatJSON {
		return writeJSON(response)
	}

	fmt.Printf("[✓] Identity created and registered\n\nID:\n%s\n", cl.Id)
	return nil
}
