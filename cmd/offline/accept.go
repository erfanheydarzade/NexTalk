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

// AcceptCommand builds the `accept` subcommand.
func (c *Command) AcceptCommand() *cobra.Command {
	var localPeer string
	var offerEnvelope string
	var inputFile string
	var outputFile string
	var inputEncoding string
	var outputEncoding string
	var format string

	cmd := &cobra.Command{
		Use:   "accept",
		Short: "Accept a handshake offer and generate an answer",
		// See encrypt.go/decrypt.go: we own all error reporting ourselves,
		// cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunAccept(AcceptOptions{
				Engine:         c.engine,
				LocalPeer:      localPeer,
				OfferEnvelope:  offerEnvelope,
				InputFile:      inputFile,
				OutputFile:     outputFile,
				InputEncoding:  inputEncoding,
				OutputEncoding: outputEncoding,
				Format:         format,
			})
			return internal.ReportAndExit(err, format)
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	// NOTE: shorthand moved from -o to -e, since -o now means --output (file).
	cmd.Flags().StringVarP(&offerEnvelope, "offerEnvelope", "e", "", "Encoded offer envelope (inline)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to a file containing the offer envelope")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write answer envelope to this file instead of stdout")

	cmd.Flags().StringVar(&inputEncoding, "in", "raw", "Input encoding (raw,b64,hex)")
	cmd.Flags().StringVar(&outputEncoding, "out", "raw", "Output encoding for stdout mode (raw,b64,hex) — ignored when --output is used")
	cmd.Flags().StringVar(&format, "format", "human", "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// AcceptOptions bundles everything RunAccept needs.
type AcceptOptions struct {
	Engine         *core.Engine
	LocalPeer      string
	OfferEnvelope  string
	InputFile      string
	OutputFile     string
	InputEncoding  string
	OutputEncoding string
	Format         string
}

func RunAccept(opts AcceptOptions) error {
	if err := internal.ValidateEncoding(opts.InputEncoding); err != nil {
		return err
	}
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

	// readInput (shared with decrypt.go) covers inline value, --file, or stdin.
	raw, err := readInput(opts.OfferEnvelope, opts.InputFile)
	if err != nil {
		return fmt.Errorf("no offer envelope provided (use -e, -f, or pipe via stdin): %w", err)
	}

	data, err := codec.DecodeInput(opts.InputEncoding, raw)
	if err != nil {
		return fmt.Errorf("failed to decode input as %s: %w", opts.InputEncoding, err)
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("failed to parse offer envelope: %w", err)
	}

	answerBytes, err := cl.AcceptOffer(env.Data)
	if err != nil {
		return fmt.Errorf("failed to accept offer: %w", err)
	}

	response := Envelope{Type: "answer", Data: answerBytes}
	output, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to encode answer envelope: %w", err)
	}

	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, output, 0o600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if opts.Format == internal.FormatJSON {
			return internal.WriteJSONResponse(AcceptResponse{Envelope: opts.OutputFile, Encoding: "file"})
		}
		fmt.Fprintf(os.Stderr, "[✓] Answer generated\n\nSaved to:\n%s\n", opts.OutputFile)
		return nil
	}

	encoded, err := codec.EncodeOutput(opts.OutputEncoding, output)
	if err != nil {
		return fmt.Errorf("failed to encode output as %s: %w", opts.OutputEncoding, err)
	}

	if opts.Format == internal.FormatJSON {
		return internal.WriteJSONResponse(AcceptResponse{Envelope: string(encoded), Encoding: opts.OutputEncoding})
	}

	if _, err := os.Stdout.Write(encoded); err != nil {
		return err
	}
	if opts.OutputEncoding != string(codec.EncodingRaw) {
		_, _ = os.Stdout.Write([]byte{'\n'})
	}
	return nil
}
