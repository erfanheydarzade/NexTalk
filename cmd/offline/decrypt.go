package offline

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/erfanheydarzade/NexTalk/internal"
	codec "github.com/erfanheydarzade/NexTalk/internal/codec"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	Encoding "github.com/erfanheydarzade/NexTalk/internal/encoding"
	"github.com/spf13/cobra"
)

// DecryptCommand builds the `decrypt` subcommand.
func (c *Command) DecryptCommand() *cobra.Command {
	var localPeer string
	var cipherText string
	var inputFile string
	var outputFile string
	var inputEncoding string
	var outputEncoding string
	var format string

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a message or file",
		// See encrypt.go: we own all error reporting, cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunDecrypt(DecryptOptions{
				Engine:         c.engine,
				LocalPeer:      localPeer,
				CipherText:     cipherText,
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
	cmd.Flags().StringVarP(&cipherText, "cipherText", "c", "", "Ciphertext to decrypt (inline)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to encrypted input file")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write decrypted payload to this file instead of stdout")

	cmd.Flags().StringVar(&inputEncoding, "in", "b64", "Input encoding (raw,b64,hex)")
	cmd.Flags().StringVar(&outputEncoding, "out", "raw", "Output encoding for stdout mode (raw,b64,hex) — ignored when --output is used")
	cmd.Flags().StringVar(&format, "format", "human", "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// DecryptOptions bundles everything RunDecrypt needs.
type DecryptOptions struct {
	Engine         *core.Engine
	LocalPeer      string
	CipherText     string
	InputFile      string
	OutputFile     string
	InputEncoding  string
	OutputEncoding string
	Format         string
}

func RunDecrypt(opts DecryptOptions) error {
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

	input, err := readInput(opts.CipherText, opts.InputFile)
	if err != nil {
		return err
	}

	input, err = codec.DecodeInput(opts.InputEncoding, input)
	if err != nil {
		return fmt.Errorf("failed to decode input as %s: %w", opts.InputEncoding, err)
	}

	senderID, plain, err := cl.Decrypt(input)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	isText := utf8.Valid(plain) && looksLikeText(plain)

	// If the user asked for a file, always write raw bytes — no JSON wrapping.
	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, plain, 0o600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if opts.Format == internal.FormatJSON {
			return writeJSON(DecryptResponse{
				Sender:   senderID,
				Encoding: "file",
				Message:  opts.OutputFile,
			})
		}
		fmt.Fprintf(os.Stderr, "[✓] Decrypted %d bytes from %s\n\nFrom:\n%s\n\nSaved to:\n%s\n",
			len(plain), sourceLabel(opts.InputFile), senderID, opts.OutputFile)
		return nil
	}

	if opts.Format == internal.FormatJSON {
		response := DecryptResponse{Sender: senderID}
		if isText {
			response.Encoding = "utf-8"
			response.Message = string(plain)
		} else {
			response.Encoding = "base64"
			response.Message = base64.StdEncoding.EncodeToString(plain)
		}
		return writeJSON(response)
	}

	// Human mode, no output file requested.
	if isText {
		fmt.Fprintf(os.Stderr, "[✓] Message decrypted\n\nFrom:\n%s\n\n", senderID)
		fmt.Printf("%s\n", string(plain))
		return nil
	}

	// Binary content but no --output given: don't dump base64 garbage to a terminal.
	if opts.OutputEncoding == string(codec.EncodingRaw) && isTTY(os.Stdout) {
		return fmt.Errorf("decrypted payload is binary (%d bytes); re-run with -o <file> to save it, or --out b64/hex to print it", len(plain))
	}

	encoded, err := codec.EncodeOutput(opts.OutputEncoding, plain)
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

func readInput(cipherText, inputFile string) ([]byte, error) {
	switch {
	case inputFile != "":
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		return data, nil
	case cipherText != "":
		return []byte(cipherText), nil
	default:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read stdin: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("no ciphertext provided (use -c, -f, or pipe via stdin)")
		}
		return data, nil
	}
}

func sourceLabel(inputFile string) string {
	if inputFile != "" {
		return inputFile
	}
	return "stdin"
}

// writeJSON writes the response as a single JSON line to stdout — this is
// the only thing programmatic consumers should ever need to parse.
func writeJSON(response DecryptResponse) error {
	output, err := Encoding.Marshal(response)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(output)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte{'\n'})
	return err
}

// looksLikeText guards against files that happen to be valid UTF-8 (zip headers,
// some binary formats) but aren't meant to be read as a message. Cheap heuristic:
// reject content with NUL bytes or a high ratio of control characters.
func looksLikeText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	controlCount := 0
	for _, b := range data {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			controlCount++
		}
	}
	return float64(controlCount)/float64(len(data)) < 0.01
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
