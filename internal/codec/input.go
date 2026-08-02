package codec

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type Encoding string

const (
	EncodingRaw  Encoding = "raw"
	EncodingBase Encoding = "b64"
	EncodingHex  Encoding = "hex"
)

// Valid reports whether the encoding is supported.
func (e Encoding) Valid() bool {
	switch e {
	case EncodingRaw, EncodingBase, EncodingHex:
		return true
	default:
		return false
	}
}

// Decode converts encoded data into raw bytes.
func Decode(enc Encoding, data []byte) ([]byte, error) {
	if !enc.Valid() {
		return nil, fmt.Errorf("unsupported encoding: %q", enc)
	}

	switch enc {
	case EncodingRaw:
		return data, nil

	case EncodingBase:
		data = bytes.TrimSpace(data)

		dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(dst, data)
		if err != nil {
			return nil, fmt.Errorf("invalid base64: %w", err)
		}

		return dst[:n], nil

	case EncodingHex:
		data = bytes.TrimSpace(data)

		dst := make([]byte, hex.DecodedLen(len(data)))
		n, err := hex.Decode(dst, data)
		if err != nil {
			return nil, fmt.Errorf("invalid hex: %w", err)
		}

		return dst[:n], nil
	}

	return nil, fmt.Errorf("unsupported encoding: %q", enc)
}

// Encode converts raw bytes into the requested encoding.
func Encode(enc Encoding, data []byte) ([]byte, error) {
	if !enc.Valid() {
		return nil, fmt.Errorf("unsupported encoding: %q", enc)
	}

	switch enc {
	case EncodingRaw:
		return data, nil

	case EncodingBase:
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(dst, data)
		return dst, nil

	case EncodingHex:
		dst := make([]byte, hex.EncodedLen(len(data)))
		hex.Encode(dst, data)
		return dst, nil
	}

	return nil, fmt.Errorf("unsupported encoding: %q", enc)
}

// DecodeInput is a helper for CLI flags.
func DecodeInput(enc string, data []byte) ([]byte, error) {
	return Decode(Encoding(enc), data)
}

// EncodeOutput is a helper for CLI flags.
func EncodeOutput(enc string, data []byte) ([]byte, error) {
	return Encode(Encoding(enc), data)
}
