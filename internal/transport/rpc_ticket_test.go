package transport

import (
	"bytes"
	"testing"

	"github.com/erfanheydarzade/nanopack"
)

func TestXferCreatedTicketRoundTrip(t *testing.T) {
	tid := bytes.Repeat([]byte{0x1}, 16)
	sec := bytes.Repeat([]byte{0x2}, 32)
	body, err := MarshalXferCreated(tid, sec, "https://shard", 999)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalXferCreated(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TransferID, tid) || !bytes.Equal(got.DownloadSecret, sec) ||
		got.ShardURL != "https://shard" || got.Expires != 999 {
		t.Fatal("round trip mismatch")
	}
	// Old response without secret is rejected.
	old, err := func() ([]byte, error) {
		enc := &nanopack.Encoder{}
		enc.AddID(1, tid)
		enc.AddID(2, putU64(999))
		return enc.Bytes()
	}()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalXferCreated(old); err == nil {
		t.Fatal("secret-less created must fail")
	}
}

func TestXferTicketAuthMatrix(t *testing.T) {
	tid := bytes.Repeat([]byte{0x1}, 16)
	mbox := bytes.Repeat([]byte{0x2}, 16)
	sec := bytes.Repeat([]byte{0x3}, 32)
	ticket := bytes.Repeat([]byte{0x4}, 32)

	// Mailbox mode unchanged.
	b, err := MarshalXferResume(tid, mbox, sec, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := UnmarshalXferResume(b)
	if err != nil || len(r.Ticket) != 0 {
		t.Fatal("mailbox mode must decode clean")
	}
	// Ticket mode.
	b, err = MarshalXferResume(tid, nil, nil, ticket, "https://shard")
	if err != nil {
		t.Fatal(err)
	}
	r, err = UnmarshalXferResume(b)
	if err != nil || !bytes.Equal(r.Ticket, ticket) || r.ShardURL != "https://shard" {
		t.Fatal("ticket mode must decode")
	}
	// Mixed rejected.
	if _, err := MarshalXferResume(tid, mbox, sec, ticket, ""); err == nil {
		t.Fatal("mixed creds must fail")
	}
	if _, err := MarshalXferResume(tid, nil, sec, ticket, ""); err == nil {
		t.Fatal("secret+ticket must fail")
	}
	if _, err := MarshalXferResume(tid, mbox, nil, ticket, ""); err == nil {
		t.Fatal("mailbox+ticket must fail")
	}
	if _, err := MarshalXferResume(tid, nil, nil, []byte{1}, ""); err == nil {
		t.Fatal("short ticket must fail")
	}

	// Same matrix for get.
	g, err := MarshalXferGet(tid, 0, mbox, sec, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	gr, err := UnmarshalXferGet(g)
	if err != nil || len(gr.Ticket) != 0 {
		t.Fatal("mailbox mode must decode clean")
	}
	g, err = MarshalXferGet(tid, 0, nil, nil, ticket, "https://shard")
	if err != nil {
		t.Fatal(err)
	}
	gr, err = UnmarshalXferGet(g)
	if err != nil || !bytes.Equal(gr.Ticket, ticket) {
		t.Fatal("ticket mode must decode")
	}
	if _, err := MarshalXferGet(tid, 0, mbox, sec, ticket, ""); err == nil {
		t.Fatal("mixed creds must fail")
	}
}
