package groupchat

import (
	"os"
	"path/filepath"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/mr-tron/base58"
)

func osGetwd() (string, error) { return os.Getwd() }
func osChdir(dir string) error { return os.Chdir(dir) }

func base58Encode(b []byte) string { return base58.Encode(b) }

func mustListContexts(t *testing.T, id string) []*multimsg.MessageContext {
	t.Helper()
	store, _, err := multimsg.OpenIdentityStores(id)
	if err != nil {
		t.Fatal(err)
	}
	ctxs, err := store.ListContexts()
	if err != nil {
		t.Fatal(err)
	}
	return ctxs
}

// handshakePair wires two identities end-to-end (offer → accept → finish).
func handshakePair(t *testing.T) (*Client.Client, *Client.Client) {
	t.Helper()
	alice := Client.NewClient()
	bob := Client.NewClient()

	offer, err := alice.CreateOffer(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := bob.AcceptOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinishHandshake(answer); err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func captureStdoutGroup(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	data := make([]byte, 0, 4096)
	buf := make([]byte, 512)
	for {
		n, err := r.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil || n == 0 {
			break
		}
	}
	return string(data)
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
