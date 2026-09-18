package filetransfer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
)

func twoClients(t *testing.T) (a, b *Client.Client) {
	t.Helper()
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	a = Client.NewClient()
	b = Client.NewClient()
	offer, err := a.CreateOffer(b.Id)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := b.AcceptOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.FinishHandshake(answer); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, a.Id+".json")); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestFileRoundTrip(t *testing.T) {
	a, b := twoClients(t)
	plain := bytes.Repeat([]byte("file-data-"), 5000) // ~50KB, multi-chunk
	cipher, chunks, mf, err := EncryptFile(a, b.Id, "demo.bin", plain, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != mf.ChunkCount || len(cipher) != mf.CipherSize {
		t.Fatal("manifest mismatch")
	}
	// Simulate transport: chunks cross as opaque copies.
	var carried [][]byte
	for _, c := range chunks {
		carried = append(carried, append([]byte(nil), c...))
	}
	got, err := ReassembleAndDecrypt(b, a.Id, carried, mf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("file mismatch")
	}
}

func TestFileCorruption(t *testing.T) {
	a, b := twoClients(t)
	plain := []byte("important bytes")
	_, chunks, mf, err := EncryptFile(a, b.Id, "x.bin", plain, 4096)
	if err != nil {
		t.Fatal(err)
	}
	chunks[0][0] ^= 0xFF // corrupt in transit
	if _, err := ReassembleAndDecrypt(b, a.Id, chunks, mf); err == nil {
		t.Fatal("corruption must fail")
	}
}

func TestFileBounds(t *testing.T) {
	a, b := twoClients(t)
	if _, _, _, err := EncryptFile(a, b.Id, "x", nil, 4096); err == nil {
		t.Fatal("empty must fail")
	}
	if _, _, _, err := EncryptFile(a, b.Id, "x", []byte("hi"), 0); err != nil {
		t.Fatal("zero chunk size must default")
	}
	if _, _, _, err := EncryptFile(a, b.Id, "x", []byte("hi"), 128*1024); err == nil {
		t.Fatal("oversize chunk must fail")
	}
}
