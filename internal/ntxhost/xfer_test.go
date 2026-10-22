package ntxhost

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func xferHost(t *testing.T, caps ...string) (*Host, *fileStore, *who) {
	t.Helper()
	fs, q, w := newFileStore(), &memQueue{}, &who{}
	h := New(Options{Spawn: fileSpawn(fs, q), Identity: w.fn})
	if _, err := h.Install(makeNTX(t, manifestJSON("q-file", "q.wasm", caps...), "q.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}
	return h, fs, w
}

func TestXferRoundTripWithFakeBinaryTransport(t *testing.T) {
	ctx := context.Background()
	a, b := pair(t)
	h, fs, w := xferHost(t, "message", "binary-transfer")

	payload := bytes.Repeat([]byte("nextalk-xfer-"), 9000) // ~117 KiB => several chunks
	var sendDone, sendTotal int
	w.set(a)
	sent, err := h.XferSend(ctx, "q-file", XferSendParams{
		Peer: b.Id, Name: `C:\fakepath\notes.bin`, Data: payload, ChunkSize: 16 * 1024,
		Progress: func(d, n int) { sendDone, sendTotal = d, n },
	})
	if err != nil {
		t.Fatal(err)
	}
	if sendTotal < 2 || sendDone != sendTotal {
		t.Fatalf("progress must report every chunk: %d/%d", sendDone, sendTotal)
	}
	if sent.Ticket == "" || len(sent.TransferID) != 32 || sent.Expires != 1234 {
		t.Fatalf("bad result: %+v", sent)
	}

	info, err := DescribeTicket(sent.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "notes.bin" || info.Size != len(payload) || info.Sender != a.Id || info.TransferID != sent.TransferID || info.Expires != nil {
		t.Fatalf("describe: %+v", info)
	}

	w.set(b)
	var recvDone int
	name, data, err := h.XferReceive(ctx, "q-file", XferReceiveParams{Ticket: sent.Ticket, Progress: func(d, n int) { recvDone = d }})
	if err != nil {
		t.Fatal(err)
	}
	if name != "notes.bin" || !bytes.Equal(data, payload) || recvDone != sendTotal {
		t.Fatalf("round trip mismatch: name=%q len=%d progress=%d", name, len(data), recvDone)
	}

	// The transport only ever saw ciphertext.
	fs.mu.Lock()
	for _, chunks := range fs.chunks {
		for _, c := range chunks {
			if bytes.Contains(c, []byte("nextalk-xfer-")) {
				t.Fatal("plaintext leaked into transfer chunks")
			}
		}
	}
	// Tamper with a stored chunk: hash check (or AEAD) must reject.
	for _, chunks := range fs.chunks {
		chunks[0][len(chunks[0])/2] ^= 0xff
	}
	fs.mu.Unlock()
	if _, _, err := h.XferReceive(ctx, "q-file", XferReceiveParams{Ticket: sent.Ticket}); err == nil {
		t.Fatal("tampered chunk must be rejected")
	}
}

func TestXferGatesAndLimits(t *testing.T) {
	ctx := context.Background()
	a, b := pair(t)

	// Declares only "message": refuse before doing anything.
	h, _, w := xferHost(t, "message")
	w.set(a)
	if _, err := h.XferSend(ctx, "q-file", XferSendParams{Peer: b.Id, Name: "x", Data: []byte("x")}); err == nil || !strings.Contains(err.Error(), "binary-transfer") {
		t.Fatalf("message-only transport must refuse xfer, got %v", err)
	}

	// Declares binary-transfer but the runtime has no transfer ops (WASM ABI v1).
	q := &memQueue{}
	h2 := New(Options{Spawn: memSpawn(q), Identity: w.fn})
	if _, err := h2.Install(makeNTX(t, manifestJSON("q-abi", "q.wasm", "message", "binary-transfer"), "q.wasm", minimalWasm), true); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.XferSend(ctx, "q-abi", XferSendParams{Peer: b.Id, Name: "x", Data: []byte("x")}); err == nil || !strings.Contains(err.Error(), "ABI v1") {
		t.Fatalf("expected the ABI-v1 limitation error, got %v", err)
	}

	h3, _, w3 := xferHost(t, "message", "binary-transfer")
	w3.set(a)
	if _, err := h3.XferSend(ctx, "q-file", XferSendParams{Peer: b.Id, Name: "big", Data: make([]byte, MaxXferBytes+1)}); err == nil {
		t.Fatal("over 8 MiB must be refused")
	}
	if _, err := h3.XferSend(ctx, "q-file", XferSendParams{Peer: b.Id, Name: "empty"}); err == nil {
		t.Fatal("empty data must be refused")
	}
	if _, _, err := h3.XferReceive(ctx, "q-file", XferReceiveParams{Ticket: "not-a-ticket"}); err == nil {
		t.Fatal("garbage ticket must be refused")
	}
}

func TestCleanName(t *testing.T) {
	for in, want := range map[string]string{"a.txt": "a.txt", "../../etc/passwd": "passwd", `C:\x\y.bin`: "y.bin", "": "file", "..": "file", "dir/": "file"} {
		if got := cleanName(in); got != want {
			t.Errorf("cleanName(%q)=%q want %q", in, got, want)
		}
	}
}
