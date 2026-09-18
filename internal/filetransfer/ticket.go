// Package filetransfer — transfer ticket convention.
//
// A ticket is how a file transfer crosses from the file relay into the
// message layer: the sender uploads to their own relay space, then sends
// this ticket inside an ordinary E2E NexTalk message (any message relay, or
// even a dedicated ticket-only message). The recipient parses it and
// fetches with the download secret alone — no mailbox, no session, no
// read_secret on the relay.
//
// Wire form is NanoPack (schema 13, registered in docs/serialization.md):
// 1=version u8, 2=transfer_id 16B raw, 3=download_secret 32B raw,
// 4=shard_url, 5=manifest bytes (embedded schema-12 body), 6=from sender
// peer ID (optional, may be empty). Binary key material travels raw, never
// hex or base64 — base64 exists only at the human copy-paste boundary
// (xfer-send prints it, xfer-recv --ticket reads it).
//
// Security: the ticket is a download-only bearer. It cannot read mailboxes,
// upload, complete, or cancel. It dies with the transfer (expiry/cancel).
// Whoever holds the message holds the file — share tickets only over
// end-to-end encrypted messages, never in the clear.
package filetransfer

import (
	"encoding/base64"
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

// TicketSchemaID is the NanoPack schema for transfer tickets.
// Registered in docs/serialization.md; never renumber.
const TicketSchemaID byte = 13

// TicketVersion is the only ticket layout version.
const TicketVersion uint8 = 2

// Ticket is a shareable file-transfer reference for message content.
type Ticket struct {
	Transfer []byte // 16B transfer ID, raw
	Secret   []byte // 32B download ticket, raw
	Shard    string // shard URL holding the transfer
	Manifest []byte // embedded schema-12 manifest body
	From     string // sender peer ID (optional, may be empty)
}

// MarshalTicket encodes a ticket to NanoPack for message content.
func MarshalTicket(t *Ticket) ([]byte, error) {
	if len(t.Transfer) != 16 {
		return nil, fmt.Errorf("filetransfer: ticket: transfer must be 16 bytes")
	}
	if len(t.Secret) != 32 {
		return nil, fmt.Errorf("filetransfer: ticket: secret must be 32 bytes")
	}
	if t.Shard == "" || len(t.Manifest) == 0 {
		return nil, fmt.Errorf("filetransfer: ticket: missing fields")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{TicketVersion})
	enc.AddID(2, t.Transfer)
	enc.AddID(3, t.Secret)
	enc.AddID(4, []byte(t.Shard))
	enc.AddID(5, t.Manifest)
	enc.AddID(6, []byte(t.From))
	raw, err := enc.Bytes()
	if err != nil {
		return nil, fmt.Errorf("filetransfer: ticket: %w", err)
	}
	return raw, nil
}

// ParseTicket validates ticket bytes from a message. The input must be the
// raw NanoPack body — JSON is rejected outright (tickets are binary; see
// EncodeTicketString for the copy-paste form).
func ParseTicket(raw []byte) (*Ticket, error) {
	if len(raw) > 0 && raw[0] == '{' {
		return nil, fmt.Errorf("filetransfer: ticket: JSON is not a ticket — pass base64 of the NanoPack ticket (see xfer-send output)")
	}
	fields, err := nanopack.DecodeID(raw)
	if err != nil {
		return nil, fmt.Errorf("filetransfer: ticket: %w", err)
	}
	var t Ticket
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 || f.Data[0] != TicketVersion {
				return nil, fmt.Errorf("filetransfer: ticket: unsupported version")
			}
		case 2:
			t.Transfer = append([]byte(nil), f.Data...)
		case 3:
			t.Secret = append([]byte(nil), f.Data...)
		case 4:
			t.Shard = string(append([]byte(nil), f.Data...))
		case 5:
			t.Manifest = append([]byte(nil), f.Data...)
		case 6:
			t.From = string(append([]byte(nil), f.Data...))
		}
	}
	if len(t.Transfer) != 16 || len(t.Secret) != 32 || t.Shard == "" || len(t.Manifest) == 0 {
		return nil, fmt.Errorf("filetransfer: ticket: missing fields")
	}
	if _, err := ParseManifest(t.Manifest); err != nil {
		return nil, fmt.Errorf("filetransfer: ticket: %w", err)
	}
	return &t, nil
}

// EncodeTicketString renders a ticket for humans to copy-paste: base64 of
// the NanoPack body. Display only — machines parse the binary.
func EncodeTicketString(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// DecodeTicketString parses the copy-paste form back to binary.
func DecodeTicketString(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("filetransfer: ticket: bad base64: %w", err)
	}
	return raw, nil
}

// Describe renders a ticket for humans (display only, never parsed).
func (t *Ticket) Describe() string {
	mf, err := ParseManifest(t.Manifest)
	name, size := "?", -1
	if err == nil {
		name, size = mf.FileName, mf.PlainSize
	}
	var from string
	if t.From != "" {
		from = " from " + shortPeer(t.From)
	}
	return fmt.Sprintf("file %q (%d bytes, transfer %.8x)%s via %s",
		name, size, t.Transfer, from, t.Shard)
}
