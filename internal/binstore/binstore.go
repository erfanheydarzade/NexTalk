// Package binstore is the shared on-disk format for NexTalk's local stores
// (contacts, mailbox, contexts, policies, deliveries).
//
// A store file is a sequence of same-schema records framed with nanopack's
// envelope (magic + version + schema ID + length + CRC16 — see
// https://github.com/erfanheydarzade/nanopack), so corruption is detected
// instead of silently misparsed:
//
//	envelope body = uvarint(recordCount)
//	                ( uvarint(len) || record ) * recordCount
//
// Each record itself is a nanopack struct body (MarshalFastID output).
package binstore

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/erfanheydarzade/nanopack"
)

// Save atomically writes records as one enveloped nanopack frame.
func Save(path string, schemaID byte, records [][]byte) error {
	body := make([]byte, 0, 64)
	body = binary.AppendUvarint(body, uint64(len(records)))
	for _, r := range records {
		body = binary.AppendUvarint(body, uint64(len(r)))
		body = append(body, r...)
	}

	frame := nanopack.WrapPacket(schemaID, body, 0)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, frame, 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

// Load reads a store file written by Save. Returns os.ErrNotExist-wrapped
// absence via ErrNotExist so callers can fall back to legacy formats.
func Load(path string, schemaID byte) ([][]byte, error) {
	frame, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	major, minor, gotSchema, _, body, _, err := nanopack.UnwrapPacket(frame)
	if err != nil {
		return nil, fmt.Errorf("unwrap %s: %w", path, err)
	}
	_ = minor
	if major != nanopack.ProtocolVersionMajor {
		return nil, fmt.Errorf("unwrap %s: unsupported protocol v%d", path, major)
	}
	if gotSchema != schemaID {
		return nil, fmt.Errorf("unwrap %s: schema %d, want %d", path, gotSchema, schemaID)
	}

	count, n := binary.Uvarint(body)
	if n <= 0 {
		return nil, fmt.Errorf("parse %s: bad record count", path)
	}
	pos := n
	out := make([][]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		ln, n := binary.Uvarint(body[pos:])
		if n <= 0 {
			return nil, fmt.Errorf("parse %s: bad record length", path)
		}
		pos += n
		if pos+int(ln) > len(body) {
			return nil, fmt.Errorf("parse %s: truncated record", path)
		}
		rec := make([]byte, ln)
		copy(rec, body[pos:pos+int(ln)])
		pos += int(ln)
		out = append(out, rec)
	}
	return out, nil
}

// Exists reports whether the store file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
