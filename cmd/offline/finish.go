package offline

import (
	"fmt"
	"os"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal"
	codec "github.com/erfanheydarzade/NexTalk/internal/codec"
	Encoding "github.com/erfanheydarzade/NexTalk/internal/encoding"
	"github.com/spf13/cobra"
)

// FinishCommand builds the `finish` subcommand.
func (c *Command) FinishCommand() *cobra.Command {
	var localPeer string
	var answerEnvelope string
	var inputFile string
	var inputEncoding string
	var format string

	cmd := &cobra.Command{
		Use:   "finish",
		Short: "Finish handshake with an answer",
		// See encrypt.go/decrypt.go: we own all error reporting ourselves,
		// cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunFinish(FinishOptions{
				Engine:         c.engine,
				LocalPeer:      localPeer,
				AnswerEnvelope: answerEnvelope,
				InputFile:      inputFile,
				InputEncoding:  inputEncoding,
				Format:         format,
			})
			return internal.ReportAndExit(err, format)
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVarP(&answerEnvelope, "answerEnvelope", "a", "", "Encoded answer envelope (inline)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to a file containing the answer envelope")
	cmd.Flags().StringVar(&inputEncoding, "in", "raw", "Input encoding (raw,b64,hex)")
	cmd.Flags().StringVar(&format, "format", "human", "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// FinishOptions bundles everything RunFinish needs.
type FinishOptions struct {
	Engine         *core.Engine
	LocalPeer      string
	AnswerEnvelope string
	InputFile      string
	InputEncoding  string
	Format         string
}

func RunFinish(opts FinishOptions) error {
	if err := internal.ValidateEncoding(opts.InputEncoding); err != nil {
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
	raw, err := readInput(opts.AnswerEnvelope, opts.InputFile)
	if err != nil {
		return fmt.Errorf("no answer envelope provided (use -a, -f, or pipe via stdin): %w", err)
	}

	data, err := codec.DecodeInput(opts.InputEncoding, raw)
	if err != nil {
		return fmt.Errorf("failed to decode input as %s: %w", opts.InputEncoding, err)
	}

	var env Envelope
	if err := Encoding.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("failed to parse answer envelope: %w", err)
	}

	peerID, err := cl.FinishHandshake(env.Data)
	if err != nil {
		return fmt.Errorf("failed to finish handshake: %w", err)
	}

	if opts.Format == internal.FormatJSON {
		return internal.WriteJSONResponse(FinishResponse{PeerID: peerID})
	}

	fmt.Fprintf(os.Stderr, "[✓] Session established\n\nPeer:\n%s\n", peerID)
	return nil
}
