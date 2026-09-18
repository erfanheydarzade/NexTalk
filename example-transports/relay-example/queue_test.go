package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenEnvelope pins byte-compat with NexTalk internal/transport:
// op=7, req_id=1, payload=[0x00] ->
// 03 | 01 01 02 04 03 01 | 07 00 00 00 01 00
func TestGoldenEnvelope(t *testing.T) {
	raw, err := hex.DecodeString("03010102040301070000000100")
	if err != nil {
		t.Fatal(err)
	}
	env, err := unmarshalEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.op != opStatus || env.reqID != 1 || !bytes.Equal(env.payload, []byte{0x00}) {
		t.Fatalf("golden mismatch: %+v", env)
	}
}

func TestQueueRoundTrip(t *testing.T) {
	dir := t.TempDir()
	q := &queue{base: dir, secrets: map[string][32]byte{}}
	secret := bytes.Repeat([]byte{0x5}, 32)
	// Mailbox for a fake 32B pub.
	pub := bytes.Repeat([]byte{0x9}, 32)
	mbox := mailboxForTest(t, pub)
	if err := q.attach(mbox, secret); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{0x03}, []byte("opaque")...)
	if err := q.send(pub, frame); err != nil {
		t.Fatal(err)
	}
	got, err := q.poll(mbox, secret, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], frame) {
		t.Fatalf("queue mismatch: %v", got)
	}
	// Burn-after-read: second poll is empty.
	got, err = q.poll(mbox, secret, 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("must drain: %v %v", got, err)
	}
	// Wrong secret fails.
	if _, err := q.poll(mbox, bytes.Repeat([]byte{0x6}, 32), 10); err == nil {
		t.Fatal("bad secret must fail")
	}
	// Files live under the mailbox dir.
	if _, err := os.Stat(filepath.Join(dir, mbox)); err != nil {
		t.Fatal(err)
	}
}

func mailboxForTest(t *testing.T, pub []byte) string {
	t.Helper()
	// Mirrors send(): hex(sha256(pub)[:16]).
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:16])
}
