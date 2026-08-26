package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// queueRelay is an in-memory relay that actually delivers envelopes, so the
// full send → listen → mailbox loop can be exercised without network I/O.
type queueRelay struct {
	mu     sync.Mutex
	queues map[string][]relay.Message // keyed by recipient Ed25519 pubkey hex
}

func newQueueRelay() *queueRelay {
	return &queueRelay{queues: make(map[string][]relay.Message)}
}

func (q *queueRelay) Register(ctx context.Context, privateKey []byte) (string, error) {
	pub, _ := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), nil
}

func (q *queueRelay) Send(ctx context.Context, recipientPubKey []byte, payload []byte, senderPriv ed25519.PrivateKey) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := hex.EncodeToString(recipientPubKey)
	q.queues[key] = append(q.queues[key], relay.Message{Body: payload})
	return nil
}

func (q *queueRelay) Receive(ctx context.Context, privateKey []byte) ([]relay.Message, error) {
	pub, _ := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	q.mu.Lock()
	defer q.mu.Unlock()
	key := hex.EncodeToString(pub)
	msgs := q.queues[key]
	delete(q.queues, key) // reads drain, like the real shard /read endpoint
	return msgs, nil
}

// chdirTemp isolates the test's <id>.json / mailbox files.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

// establishedPair creates two identities with a completed Double Ratchet
// handshake and registers both with the queue relay.
func establishedPair(t *testing.T, r *queueRelay) (*Client.Client, *Client.Client) {
	t.Helper()

	alice := Client.NewClient()
	bob := Client.NewClient()
	ctx := context.Background()

	if _, err := r.Register(ctx, alice.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, bob.IdentityPrivate); err != nil {
		t.Fatal(err)
	}

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

// sendDirectMessage replicates what `worker encrypt` does: 1:1 encrypt +
// TypeMessage envelope to the peer's queue.
func sendDirectMessage(t *testing.T, from *Client.Client, to *Client.Client, r *queueRelay, body string) {
	t.Helper()
	cipher, err := from.Encrypt(to.Id, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ed25519PubFromID(to.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(context.Background(), pub, relay.WrapEnvelope(relay.TypeMessage, cipher), from.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
}

// TestListenThenMailboxCLI is THE regression test for the reported bug:
// "the messages is sent, listen shows 'a new message from *', but then you
// write `mailbox <id>` it shows nothing."
//
// The CLI listen must persist every decrypted message so the one-shot
// mailbox command — possibly run later, in a different process — can read
// the same history.
func TestListenThenMailboxCLI(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()
	alice, bob := establishedPair(t, r)

	sendDirectMessage(t, alice, bob, r, "where are you?")

	// Bob polls once — exactly what `nextalk worker listen -i bob` does.
	c := &Command{engine: core.NewEngine(), cfg: config.Config{}, testRelay: r}
	if err := c.RunListen(context.Background(), bob.Id, formatJSON); err != nil {
		t.Fatalf("listen: %v", err)
	}

	// The message must now be in bob's persistent mailbox…
	store, err := mailbox.Load(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	thread, ok := store.Get(alice.Id)
	if !ok {
		t.Fatal("message not stored by listen — mailbox would show nothing")
	}
	if len(thread.Messages) != 1 || thread.Messages[0].Body != "where are you?" {
		t.Fatalf("unexpected stored thread: %+v", thread)
	}
	if thread.Messages[0].IsRead {
		t.Error("freshly received message must be unread")
	}

	// …and the mailbox command must surface it (human output path).
	out := captureStdout(t, func() {
		if err := groupchat.RunMailbox(bob.Id, []string{alice.Id}); err != nil {
			t.Errorf("mailbox: %v", err)
		}
	})
	if !strings.Contains(out, "where are you?") {
		t.Errorf("mailbox output missing message body:\n%s", out)
	}
	if strings.Contains(out, "[multi]") || !utf8Printable(out) {
		t.Errorf("mailbox output contains garbage:\n%s", out)
	}

	// Reading marks it read; verify the read state was persisted by
	// reopening the store fresh (as another process would see it).
	reopened, err := mailbox.Load(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.UnreadTotal(); got != 0 {
		t.Errorf("UnreadTotal after mailbox read = %d, want 0", got)
	}
}

// TestListenGroupMessageStoresUnderContext extends the regression to group
// chat: a send-multi delivery heard via listen must land in a named group
// thread — with the sender-embedded context metadata adopted locally —
// instead of being dumped into the sender's DM as binary garbage.
func TestListenGroupMessageStoresUnderContext(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()
	alice, bob := establishedPair(t, r)

	// Alice creates "Design Crew" with bob as member and fans out a message.
	aliceCtxStore, err := multimsg.NewJSONContextStore(alice.Id+".contexts.json", alice.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	aliceDeliveries, err := multimsg.NewJSONDeliveryStore(alice.Id + ".deliveries.json")
	if err != nil {
		t.Fatal(err)
	}
	aliceFan := multimsg.NewFanout(alice, r, aliceCtxStore, aliceDeliveries, multimsg.DefaultFanoutConfig())

	groupMeta, err := aliceFan.CreateContext("Design Crew", alice.IdentityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceFan.SetRecipientPolicy(groupMeta.ContextID, bob.Id, multimsg.PolicyEnabled); err != nil {
		t.Fatal(err)
	}
	result, err := aliceFan.SendMultiMessage(context.Background(), groupMeta.ContextID, []byte("standup at 10"), []string{bob.Id})
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	for _, d := range result.Deliveries {
		if d.Status == multimsg.DeliverySent {
			sent++
		}
	}
	if sent != 1 {
		t.Fatalf("expected 1 sent delivery, got %d", sent)
	}

	// Bob listens — the envelope arrives as TypeMultiMsg (0x04).
	c := &Command{engine: core.NewEngine(), cfg: config.Config{}, testRelay: r}
	if err := c.RunListen(context.Background(), bob.Id, formatHuman); err != nil {
		t.Fatalf("listen: %v", err)
	}

	store, err := mailbox.Load(bob.Id)
	if err != nil {
		t.Fatal(err)
	}

	// Group thread keyed by the real context ID, titled with the signed
	// display name learned from the wire — not "ctx:<sender>" garbage.
	key, err := store.ResolveThread("Design Crew")
	if err != nil {
		t.Fatalf("group thread missing after listen: %v", err)
	}
	msgs, err := store.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 group message, got %d", len(msgs))
	}
	if msgs[0].Body != "standup at 10" {
		t.Errorf("group body = %q, want clean plaintext", msgs[0].Body)
	}
	if msgs[0].Sender != alice.Id {
		t.Errorf("group sender = %q, want alice", msgs[0].Sender)
	}

	// Bob's context store should have adopted the remote metadata too.
	bobCtxStore, err := multimsg.NewJSONContextStore(bob.Id+".contexts.json", bob.Id+".policies.json")
	if err == nil {
		if stored, err := bobCtxStore.LoadContext(groupMeta.ContextID); err == nil && stored.DisplayName != "Design Crew" {
			t.Errorf("adopted display name = %q", stored.DisplayName)
		}
	}

	// And the human mailbox view renders the group by name.
	out := captureStdout(t, func() {
		if err := groupchat.RunMailbox(bob.Id, nil); err != nil {
			t.Errorf("mailbox list: %v", err)
		}
	})
	if !strings.Contains(out, "Design Crew") {
		t.Errorf("mailbox list missing group name:\n%s", out)
	}
}

// ── test helpers ──────────────────────────────────────────────────────────────

func captureStdout(t *testing.T, fn func()) string {
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
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func utf8Printable(s string) bool {
	for _, r := range s {
		if r != '\n' && r != '\t' && (r < 32 || r == 0xFFFD) {
			return false
		}
	}
	return true
}
