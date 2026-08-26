package worker

import (
	"context"
	"fmt"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

// ConnectCommand builds the `connect` subcommand.
func (c *Command) ConnectCommand() *cobra.Command {
	var localPeer string
	var remotePeer string
	var format string

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Send a handshake offer to a peer via the worker",
		// We own all error reporting (human vs json) — cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.RunConnect(localPeer, remotePeer, format)
			return reportAndExit(err, format)
		},
		// Tab completion for the -r slot: established peers + contact aliases.
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return groupchat.FilterByPrefix(groupchat.PeerCandidates(flagString(cmd, "id")), toComplete),
				cobra.ShellCompDirectiveNoFileComp
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVarP(&remotePeer, "remotePeer", "r", "", "Remote peer ID")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")

	return cmd
}

func (c *Command) RunConnect(localPeer string, remotePeer string, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}

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

	cl, err := Client.LoadClient(localPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	offerBytes, err := cl.CreateOffer(remotePeer)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}

	if err := sendEnvelope(
		ctx,
		r,
		cl.IdentityPrivate,
		peerPubKey,
		relay.TypeOffer,
		offerBytes,
	); err != nil {
		return fmt.Errorf("send offer: %w", err)
	}

	response := ConnectResponse{
		Success: true,
		Peer:    remotePeer,
		Message: "Offer sent successfully.",
	}

	if format == formatJSON {
		return writeJSON(response)
	}

	fmt.Printf("[✓] Offer sent\n\nTo:\n%s\n", remotePeer)
	return nil
}
