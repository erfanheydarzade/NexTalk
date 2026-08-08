package offline

import (
	"encoding/json"
	"fmt"
	"os"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal"
	codec "github.com/erfanheydarzade/NexTalk/internal/codec"
	"github.com/spf13/cobra"
)

// OfferCommand builds the `offer` subcommand.
func (c *Command) OfferCommand() *cobra.Command {
	var localPeer string
	var remotePeer string
	var outputFile string
	var outputEncoding string
	var format string

	cmd := &cobra.Command{
		Use:   "offer",
		Short: "Generate a handshake offer",
		// See encrypt.go/decrypt.go: we own all error reporting ourselves,
		// cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunOffer(OfferOptions{
				Engine:         c.engine,
				LocalPeer:      localPeer,
				RemotePeer:     remotePeer,
				OutputFile:     outputFile,
				OutputEncoding: outputEncoding,
				Format:         format,
			})
			return internal.ReportAndExit(err, format)
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVarP(&remotePeer, "remotePeer", "r", "", "Remote peer ID")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write offer envelope to this file instead of stdout")

	cmd.Flags().StringVar(&outputEncoding, "out", "raw", "Output encoding for stdout mode (raw,b64,hex) — ignored when --output is used")
	cmd.Flags().StringVar(&format, "format", "human", "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")

	return cmd
}

// OfferOptions bundles everything RunOffer needs.
type OfferOptions struct {
	Engine         *core.Engine
	LocalPeer      string
	RemotePeer     string
	OutputFile     string
	OutputEncoding string
	Format         string
}

func RunOffer(opts OfferOptions) error {
	if err := internal.ValidateEncoding(opts.OutputEncoding); err != nil {
		return err
	}
	if err := internal.ValidateFormat(opts.Format); err != nil {
		return err
	}

	cl, err := Client.LoadClient(opts.LocalPeer)
	if err != nil {
		return fmt.Errorf("failed to load local peer %q: %w", opts.LocalPeer, err)
	}

	offerBytes, err := cl.CreateOffer(opts.RemotePeer)
	if err != nil {
		return fmt.Errorf("failed to create offer for %q: %w", opts.RemotePeer, err)
	}

	env := Envelope{Type: "offer", Data: offerBytes}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to encode offer envelope: %w", err)
	}

	// If the user asked for a file, always write the raw envelope bytes —
	// no re-encoding, no JSON wrapping (mirrors encrypt.go/decrypt.go).
	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, envBytes, 0o600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if opts.Format == internal.FormatJSON {
			return internal.WriteJSONResponse(OfferResponse{
				RemotePeer: opts.RemotePeer,
				Envelope:   opts.OutputFile,
				Encoding:   "file",
			})
		}
		fmt.Fprintf(os.Stderr, "[✓] Offer created for %s\n\nSaved to:\n%s\n", opts.RemotePeer, opts.OutputFile)
		return nil
	}

	encoded, err := codec.EncodeOutput(opts.OutputEncoding, envBytes)
	if err != nil {
		return fmt.Errorf("failed to encode output as %s: %w", opts.OutputEncoding, err)
	}

	if opts.Format == internal.FormatJSON {
		return internal.WriteJSONResponse(OfferResponse{
			RemotePeer: opts.RemotePeer,
			Envelope:   string(encoded),
			Encoding:   opts.OutputEncoding,
		})
	}

	if _, err := os.Stdout.Write(encoded); err != nil {
		return err
	}
	if opts.OutputEncoding != string(codec.EncodingRaw) {
		_, _ = os.Stdout.Write([]byte{'\n'})
	}
	return nil
}
