package worker

import (
	"errors"
	"fmt"
	"io"
	"os"

	codec "github.com/erfanheydarzade/NexTalk/internal/codec"
	Encoding "github.com/erfanheydarzade/NexTalk/internal/encoding"
)

// Output format constants — same contract as the offline package: "human"
// prints status to stderr and data to stdout; "json" prints exactly one
// JSON object to stdout and nothing else.
const (
	formatHuman = "human"
	formatJSON  = "json"
)

// errorResponse is the JSON shape used to report failures when --format json
// is active, so programmatic consumers get a parseable object either way.
type errorResponse struct {
	Error string `json:"error"`
}

func validateEncoding(enc string) error {
	switch codec.Encoding(enc) {
	case codec.EncodingRaw, codec.EncodingBase, codec.EncodingHex:
		return nil
	default:
		return fmt.Errorf("invalid encoding %q (want raw, b64, or hex)", enc)
	}
}

func validateFormat(format string) error {
	switch format {
	case formatHuman, formatJSON:
		return nil
	default:
		return fmt.Errorf("invalid format %q (want human or json)", format)
	}
}

// reportAndExit renders err in the requested format and returns it unchanged
// so cobra can still translate it into a non-zero exit code. Commands must
// set SilenceUsage/SilenceErrors so cobra never prints its own error on top
// of this.
func reportAndExit(err error, format string) error {
	if err == nil {
		return nil
	}
	if format == formatJSON {
		_ = writeJSON(errorResponse{Error: err.Error()})
	} else {
		fmt.Fprintf(os.Stderr, "[✗] %v\n", err)
	}
	return err
}

// writeJSON writes v as a single JSON line to stdout — the only thing a
// programmatic consumer should ever need to parse.
func writeJSON(v interface{}) error {
	output, err := Encoding.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(output); err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte{'\n'})
	return err
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// readPayload resolves a plaintext/ciphertext payload the same way the
// offline commands do: explicit inline value, then file, then stdin — and
// decodes it according to inputEncoding (raw/b64/hex). If stdin is an
// interactive TTY with nothing piped in, it fails fast instead of blocking.
func readPayload(inline, inputFile, inputEncoding string) ([]byte, error) {
	var raw []byte

	switch {
	case inputFile != "":
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		raw = data

	case inline != "":
		raw = []byte(inline)

	default:
		fi, err := os.Stdin.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat stdin: %w", err)
		}
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			return nil, errors.New("no input provided: pass -m/-c, -f, or pipe data via stdin")
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(data) == 0 {
			return nil, errors.New("no input provided")
		}
		raw = data
	}

	decoded, err := codec.DecodeInput(inputEncoding, raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input as %s: %w", inputEncoding, err)
	}
	return decoded, nil
}
