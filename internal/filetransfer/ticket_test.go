package filetransfer

import (
	"bytes"
	"strings"
	"testing"
)

func testManifest(t *testing.T) []byte {
	t.Helper()
	mf := &Manifest{
		FileName:   "photo.bin",
		PlainSize:  12,
		CipherSize: 60,
		ChunkSize:  32,
		ChunkCount: 2,
		FileHash:   bytes.Repeat([]byte{0xA}, 32),
		CipherHash: bytes.Repeat([]byte{0xB}, 32),
	}
	return mf.Bytes()
}

func TestTicketRoundTrip(t *testing.T) {
	raw, err := MarshalTicket(&Ticket{
		Transfer: bytes.Repeat([]byte{0x1}, 16),
		Secret:   bytes.Repeat([]byte{0x2}, 32),
		Shard:    "https://shard",
		Manifest: testManifest(t),
		From:     "peer1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 0 && raw[0] == '{' {
		t.Fatal("ticket must be binary, not JSON")
	}
	got, err := ParseTicket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Transfer, bytes.Repeat([]byte{0x1}, 16)) ||
		!bytes.Equal(got.Secret, bytes.Repeat([]byte{0x2}, 32)) ||
		got.Shard != "https://shard" || got.From != "peer1" {
		t.Fatal("round trip mismatch")
	}
	mf, err := ParseManifest(got.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if mf.FileName != "photo.bin" || mf.ChunkCount != 2 {
		t.Fatal("embedded manifest mismatch")
	}
	// Copy-paste form round-trips through base64.
	s := EncodeTicketString(raw)
	back, err := DecodeTicketString(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatal("base64 form must preserve bytes")
	}
	if _, err := ParseTicket(back); err != nil {
		t.Fatal(err)
	}
	// Human description mentions the file, never the secret.
	desc := got.Describe()
	if !strings.Contains(desc, "photo.bin") || strings.Contains(desc, strings.Repeat("2", 10)) {
		t.Fatalf("bad description: %s", desc)
	}
}

func TestTicketRejects(t *testing.T) {
	good, err := MarshalTicket(&Ticket{
		Transfer: bytes.Repeat([]byte{0x1}, 16),
		Secret:   bytes.Repeat([]byte{0x2}, 32),
		Shard:    "https://shard",
		Manifest: testManifest(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = good
	cases := [][]byte{
		{},
		[]byte(`{}`),
		[]byte(`{"v":2,"transfer":"` + strings.Repeat("a", 32) + `"}`),
		[]byte("not nanopack \x00\x01"),
		mustMarshal(t, &Ticket{ // short transfer
			Transfer: []byte{1, 2}, Secret: bytes.Repeat([]byte{0x2}, 32),
			Shard: "s", Manifest: testManifest(t),
		}, true),
		mustMarshal(t, &Ticket{ // short secret
			Transfer: bytes.Repeat([]byte{0x1}, 16), Secret: []byte{1},
			Shard: "s", Manifest: testManifest(t),
		}, true),
		mustMarshal(t, &Ticket{ // empty shard
			Transfer: bytes.Repeat([]byte{0x1}, 16), Secret: bytes.Repeat([]byte{0x2}, 32),
			Shard: "", Manifest: testManifest(t),
		}, true),
	}
	for i, raw := range cases {
		if raw == nil {
			continue // marshal correctly refused; nothing to parse
		}
		if _, err := ParseTicket(raw); err == nil {
			t.Fatalf("case %d must fail", i)
		}
	}
	// A well-formed ticket with a corrupt embedded manifest marshals fine
	// (manifest is opaque to the ticket layer) but fails at parse.
	corrupt, err := MarshalTicket(&Ticket{
		Transfer: bytes.Repeat([]byte{0x1}, 16), Secret: bytes.Repeat([]byte{0x2}, 32),
		Shard: "s", Manifest: []byte{0x05, 0x01, 0x02},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTicket(corrupt); err == nil {
		t.Fatal("corrupt embedded manifest must fail parse")
	}
	// Bad base64 rejected.
	if _, err := DecodeTicketString("!!!"); err == nil {
		t.Fatal("bad base64 must fail")
	}
}

// mustMarshal returns nil when MarshalTicket correctly refuses (wantFail).
func mustMarshal(t *testing.T, tk *Ticket, wantFail bool) []byte {
	t.Helper()
	raw, err := MarshalTicket(tk)
	if wantFail {
		if err == nil {
			t.Fatalf("marshal must refuse: %+v", tk)
		}
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManifestRoundTrip(t *testing.T) {
	raw := testManifest(t)
	mf, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if mf.FileName != "photo.bin" || mf.PlainSize != 12 || mf.CipherSize != 60 ||
		mf.ChunkSize != 32 || mf.ChunkCount != 2 ||
		!bytes.Equal(mf.FileHash, bytes.Repeat([]byte{0xA}, 32)) ||
		!bytes.Equal(mf.CipherHash, bytes.Repeat([]byte{0xB}, 32)) {
		t.Fatal("manifest round trip mismatch")
	}
	if _, err := ParseManifest([]byte{}); err == nil {
		t.Fatal("empty manifest must fail")
	}
	if _, err := ParseManifest([]byte(`{"file_name":"x"}`)); err == nil {
		t.Fatal("JSON manifest must fail")
	}
}
