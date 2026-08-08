package internal

import (
	"encoding/json"
	"fmt"
	"os"

	codec "github.com/erfanheydarzade/NexTalk/internal/codec"
)

const (
	FormatHuman = "human"
	FormatJSON  = "json"
)

// ErrorResponse is the JSON shape emitted on failure when --format json is
// set, so programmatic consumers always get a parseable object regardless
// of whether the command succeeded or failed.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ReportAndExit is the single place that turns a RunEncrypt/RunDecrypt error
// into user/consumer-facing output and a process exit code. It must be the
// last thing called from every subcommand's RunE so that:
//   - human mode errors go to stderr as plain text
//   - json mode errors go to stdout as a single JSON object (never cobra's
//     default "Error: ..." text, which SilenceErrors/SilenceUsage prevent)
//   - the process exits non-zero on any error, in both modes
func ReportAndExit(err error, format string) error {
	if err == nil {
		return nil
	}

	if format == FormatJSON {
		out, marshalErr := json.Marshal(ErrorResponse{Error: err.Error()})
		if marshalErr == nil {
			fmt.Fprintln(os.Stdout, string(out))
		} else {
			// Marshal itself failed: fall back to a hand-built JSON object
			// so output stays parseable even in this edge case.
			fmt.Fprintf(os.Stdout, "{\"error\":%q}\n", err.Error())
		}
	} else {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	os.Exit(1)
	return nil // unreachable, kept for signature compatibility
}

// WriteJSONResponse marshals any response value as a single JSON line to
// stdout. This is the generic counterpart to decrypt.go's writeJSON (which
// is typed to DecryptResponse) — used by offer/accept/finish/init so every
// subcommand emits the same single-line-JSON contract for --format json.
func WriteJSONResponse(response interface{}) error {
	out, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(out); err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte{'\n'})
	return err
}

// ValidateEncoding rejects unknown --in/--out values up front instead of
// letting them fail deep inside codec.DecodeInput/EncodeOutput with a less
// clear error.
func ValidateEncoding(enc string) error {
	switch enc {
	case string(codec.EncodingRaw), "b64", "hex":
		return nil
	default:
		return fmt.Errorf("invalid encoding %q: must be one of raw, b64, hex", enc)
	}
}

// ValidateFormat rejects unknown --format values up front.
func ValidateFormat(format string) error {
	switch format {
	case FormatHuman, FormatJSON:
		return nil
	default:
		return fmt.Errorf("invalid format %q: must be one of human, json", format)
	}
}
