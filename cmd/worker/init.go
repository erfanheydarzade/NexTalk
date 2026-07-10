package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func (c *Command) InitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize identity and register a mailbox with the worker",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.RunInit(cmd.Context())
		},
	}
}

func (c *Command) RunInit(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl := c.engine.Initialize()

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

	response := InitResponse{
		ID: cl.Id,
	}

	output, err := json.Marshal(response)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}
