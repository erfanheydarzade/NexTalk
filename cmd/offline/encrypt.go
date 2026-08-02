package offline

import (
	"fmt"
	"io"
	"os"

	"github.com/erfanheydarzade/NexTalk/internal"
	codec "github.com/erfanheydarzade/NexTalk/internal/codec"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/spf13/cobra"
)

// EncryptCommand builds the `encrypt` subcommand.
func (c *Command) EncryptCommand() *cobra.Command {
	var localPeer string
	var remotePeer string
	var message string
	var inputFile string
	var outputFile string
	var inputEncoding string
	var outputEncoding string
	var format string

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a message or file",
		// SilenceUsage/SilenceErrors: we take full control of error reporting
		// ourselves (human vs json), so cobra must never print its own
		// "Error: ..." line or usage block on top of what we already emit.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunEncrypt(EncryptOptions{
				Engine:         c.engine,
				LocalPeer:      localPeer,
				RemotePeer:     remotePeer,
				Message:        message,
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
	cmd.Flags().StringVarP(&remotePeer, "remotePeer", "r", "", "Remote peer ID")
	cmd.Flags().StringVarP(&message, "message", "m", "", "Message to encrypt (inline)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to plaintext input file")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write encrypted payload to this file instead of stdout")

	cmd.Flags().StringVar(&inputEncoding, "in", "raw", "Input encoding (raw,b64,hex)")
	cmd.Flags().StringVar(&outputEncoding, "out", "raw", "Output encoding for stdout mode (raw,b64,hex) — ignored when --output is used")
	cmd.Flags().StringVar(&format, "format", "human", "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("remotePeer")

	return cmd
}

// EncryptOptions bundles everything RunEncrypt needs.
type EncryptOptions struct {
	Engine         *core.Engine
	LocalPeer      string
	RemotePeer     string
	Message        string
	InputFile      string
	OutputFile     string
	InputEncoding  string
	OutputEncoding string
	Format         string
}

func RunEncrypt(opts EncryptOptions) error {
	if err := internal.ValidateFormat(opts.InputEncoding); err != nil {
		return err
	}
	if err := internal.ValidateFormat(opts.OutputEncoding); err != nil {
		return err
	}
	if err := internal.ValidateFormat(opts.Format); err != nil {
		return err
	}

	cl, err := Client.LoadClient(opts.LocalPeer)
	if err != nil {
		return fmt.Errorf("failed to load local peer %q: %w", opts.LocalPeer, err)
	}

	plaintext, err := readPlaintext(opts.Message, opts.InputFile)
	if err != nil {
		return err
	}

	plaintext, err = codec.DecodeInput(opts.InputEncoding, plaintext)
	if err != nil {
		return fmt.Errorf("failed to decode input as %s: %w", opts.InputEncoding, err)
	}

	output, err := cl.Encrypt(opts.RemotePeer, plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, output, 0o600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if opts.Format == internal.FormatJSON {
			return writeJSON(DecryptResponse{
				Sender:   opts.RemotePeer,
				Encoding: "file",
				Message:  opts.OutputFile,
			})
		}
		// Status/progress messages always go to stderr so that stdout stays
		// clean for any programmatic consumer piping this command's output.
		fmt.Fprintf(os.Stderr, "[✓] Encrypted %d bytes for %s\n\nSaved to:\n%s\n",
			len(plaintext), opts.RemotePeer, opts.OutputFile)
		return nil
	}

	if opts.Format == internal.FormatJSON {
		encoded, err := codec.EncodeOutput(opts.OutputEncoding, output)
		if err != nil {
			return fmt.Errorf("failed to encode output as %s: %w", opts.OutputEncoding, err)
		}
		return writeJSON(DecryptResponse{
			Sender:   opts.RemotePeer,
			Encoding: opts.OutputEncoding,
			Message:  string(encoded),
		})
	}

	// Human mode, no output file: ciphertext is opaque binary, so refuse to
	// splash it across an interactive terminal unless it's actually encoded text.
	if opts.OutputEncoding == string(codec.EncodingRaw) && isTTY(os.Stdout) {
		return fmt.Errorf("encrypted payload is binary (%d bytes); re-run with -o <file> to save it, or --out b64/hex to print it", len(output))
	}

	encoded, err := codec.EncodeOutput(opts.OutputEncoding, output)
	if err != nil {
		return fmt.Errorf("failed to encode output as %s: %w", opts.OutputEncoding, err)
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return err
	}
	if opts.OutputEncoding != string(codec.EncodingRaw) {
		_, _ = os.Stdout.Write([]byte{'\n'})
	}
	return nil
}

func readPlaintext(message, inputFile string) ([]byte, error) {
	switch {
	case inputFile != "":
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		return data, nil
	case message != "":
		return []byte(message), nil
	default:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read stdin: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("no plaintext provided (use -m, -f, or pipe via stdin)")
		}
		return data, nil
	}
}
