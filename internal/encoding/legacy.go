// legacy.go restores the original text-based binmodel API (NewEncoder,
// Decode, Marshal) referenced in encoding2.go's doc comment but missing
// from this checkout. It is intentionally separate from the v2 (Encoder2/
// Decode2/Schema) API and untouched by it — this is the pre-v2 wire format
// used by crypto.SecureMessage (kex_hybrid.go) and by internal's generic
// JSON error responses.
//
// Wire format (v1):
//
//	field := name ":" base64(data)
//	payload := field ("," field)*
//
// Field name and value are joined with ':' and fields are joined with
// ','. Values are base64-encoded so they can never themselves contain a
// ':' or ',', which keeps decoding a simple two-level split — no escaping
// needed.
package encoding

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Encoder builds a v1 payload. Zero value is not usable; use NewEncoder.
// Add/AddString return the encoder itself so calls can be chained, e.g.:
//
//	wire := NewEncoder().
//	    AddString("s", msg.SenderID).
//	    Add("k", msg.RatchetKey).
//	    Bytes()
type Encoder struct {
	fields []string
}

// NewEncoder creates an empty v1 encoder.
func NewEncoder() *Encoder {
	return &Encoder{}
}

// Add appends a field by name with raw bytes, base64-encoding the value.
func (e *Encoder) Add(name string, data []byte) *Encoder {
	e.fields = append(e.fields, name+":"+base64.StdEncoding.EncodeToString(data))
	return e
}

// AddString appends a field by name with a string value (convenience
// wrapper around Add).
func (e *Encoder) AddString(name string, val string) *Encoder {
	return e.Add(name, []byte(val))
}

// Bytes serializes all added fields into the final v1 wire payload.
func (e *Encoder) Bytes() []byte {
	return []byte(strings.Join(e.fields, ","))
}

// Reset clears the encoder for reuse.
func (e *Encoder) Reset() {
	e.fields = e.fields[:0]
}

// Decode parses a v1 payload produced by Encoder into name -> raw bytes.
// Unknown fields are simply included in the map; callers look up only the
// names they expect (see crypto.SecureMessage's Decrypt).
func Decode(payload []byte) (map[string][]byte, error) {
	out := make(map[string][]byte)
	s := string(payload)
	if s == "" {
		return out, nil
	}

	for _, field := range strings.Split(s, ",") {
		idx := strings.IndexByte(field, ':')
		if idx < 0 {
			return nil, fmt.Errorf("binmodel: malformed field %q: missing ':'", field)
		}
		name := field[:idx]
		valB64 := field[idx+1:]

		data, err := base64.StdEncoding.DecodeString(valB64)
		if err != nil {
			return nil, fmt.Errorf("binmodel: invalid base64 for field %q: %w", name, err)
		}
		out[name] = data
	}

	return out, nil
}

// Marshal is a generic JSON-based marshal used by callers across cmd/
// (offline offer/accept/finish/decrypt, worker) and internal's
// ErrorResponse/WriteJSONResponse that just need "any struct -> bytes"
// and aren't part of the binmodel wire protocol proper. It's a thin
// wrapper over encoding/json so those callers get normal JSON semantics
// (respecting `json:"..."` struct tags) via this package's alias.
func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal is the counterpart to Marshal, used by offline accept/finish
// to decode JSON request/response bodies.
func Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
