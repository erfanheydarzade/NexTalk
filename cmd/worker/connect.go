package worker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

func (c *Command) ConnectCommand() *cobra.Command {
	var localPeer string
	var remotePeer string

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Send a handshake offer to a peer via the worker",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.RunConnect(localPeer, remotePeer)
		},
	}

	cmd.Flags().StringVarP(
		&localPeer,
		"id",
		"i",
		"",
		"Local peer ID",
	)

	cmd.Flags().StringVarP(
		&remotePeer,
		"remotePeer",
		"r",
		"",
		"Remote peer ID",
	)

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")

	return cmd
}

func (c *Command) RunConnect(localPeer string, remotePeer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	peerPubKey, err := ed25519PubFromID(remotePeer)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl, err := c.engine.LoadClient(localPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	offerBytes, err := c.engine.CreateOffer(remotePeer)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}

	resp := ConnectResponse{
		Success: true,
		Message: "Offer sent successfully.",
	}

	if err := sendEnvelope(
		ctx,
		r,
		cl.IdentityPrivate,
		peerPubKey,
		relay.TypeOffer,
		offerBytes,
	); err != nil {
		resp.Success = false
		resp.Message = "Offer send failed"
	}

	output, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
