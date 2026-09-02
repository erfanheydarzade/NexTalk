package worker

import (
	"context"
	"fmt"

	Client "github.com/erfanheydarzade/NexTalk/client"
	codec "github.com/erfanheydarzade/NexTalk/internal/codec"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

// EncryptCommand builds the `worker encrypt` subcommand.
func (c *Command) EncryptCommand() *cobra.Command {
	var localPeer string
	var remotePeer string
	var message string
	var inputFile string
	var inputEncoding string
	var outputEncoding string
	var format string

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a message or file and dispatch it via the worker",
		// We own all error reporting (human vs json) — cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.RunEncrypt(
				cmd.Context(),
				EncryptWorkerOptions{
					LocalPeer:      localPeer,
					RemotePeer:     remotePeer,
					Message:        message,
					InputFile:      inputFile,
					InputEncoding:  inputEncoding,
					OutputEncoding: outputEncoding,
					Format:         format,
				},
			)
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
	cmd.Flags().StringVarP(&message, "message", "m", "", "Message to encrypt (inline)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to plaintext input file")

	cmd.Flags().StringVar(&inputEncoding, "in", string(codec.EncodingRaw), "Input encoding (raw,b64,hex)")
	cmd.Flags().StringVar(&outputEncoding, "out", "b64", "Encoding used to echo the sent ciphertext")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")

	return cmd
}

// EncryptWorkerOptions bundles everything RunEncrypt needs.
type EncryptWorkerOptions struct {
	LocalPeer      string
	RemotePeer     string
	Message        string
	InputFile      string
	InputEncoding  string
	OutputEncoding string
	Format         string
}

func (c *Command) RunEncrypt(ctx context.Context, opts EncryptWorkerOptions) error {
	if err := validateEncoding(opts.InputEncoding); err != nil {
		return err
	}
	if err := validateEncoding(opts.OutputEncoding); err != nil {
		return err
	}
	if err := validateFormat(opts.Format); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl, err := Client.LoadClient(opts.LocalPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	peerPubKey, err := ed25519PubFromID(opts.RemotePeer)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	plaintext, err := readPayload(opts.Message, opts.InputFile, opts.InputEncoding)
	if err != nil {
		return err
	}

	cipherBytes, err := cl.Encrypt(opts.RemotePeer, plaintext)
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
		return fmt.Errorf("send message: %w", err)
	}

	encoded, err := codec.EncodeOutput(opts.OutputEncoding, cipherBytes)
	if err != nil {
		return fmt.Errorf("failed to encode output as %s: %w", opts.OutputEncoding, err)
	}

	response := EncryptResponse{
		Peer:     opts.RemotePeer,
		Encoding: opts.OutputEncoding,
		Message:  string(encoded),
	}

	if opts.Format == formatJSON {
		return writeJSON(response)
	}

	fmt.Printf("[✓] Encrypted %d bytes and sent\n\nTo:\n%s\n", len(plaintext), opts.RemotePeer)
	return nil
}
