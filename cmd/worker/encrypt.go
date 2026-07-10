package worker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

func (c *Command) EncryptCommand() *cobra.Command {
	var localPeer string
	var remotePeer string
	var message string

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt and Encrypt a message",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.RunEncrypt(
				cmd.Context(),
				localPeer,
				remotePeer,
				message,
			)
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
	cmd.Flags().StringVarP(
		&message,
		"message",
		"m",
		"",
		"Message to encrypt",
	)

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")
	_ = cmd.MarkFlagRequired("message")

	return cmd
}

func (c *Command) RunEncrypt(
	ctx context.Context,
	localPeer string,
	remotePeer string,
	message string,
) error {

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl, err := c.engine.LoadClient(localPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	peerPubKey, err := ed25519PubFromID(remotePeer)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	cipherBytes, err := c.engine.Encrypt(remotePeer, message)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := sendEnvelope(
		ctx,
		r,
		cl.IdentityPrivate,
		peerPubKey,
		relay.TypeMessage,
		cipherBytes,
	); err != nil {
		return fmt.Errorf("Encrypt message: %w", err)
	}

	output, err := json.Marshal(EncryptResponse{
		Peer: remotePeer,
	})
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}
