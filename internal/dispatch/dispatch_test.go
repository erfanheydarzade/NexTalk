package dispatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// twoClients handshakes A↔B in memory and returns them.
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
	// Persisted session files exist; reload to prove store independence.
	if _, err := os.Stat(filepath.Join(dir, a.Id+".json")); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestDispatchMessage(t *testing.T) {
	a, b := twoClients(t)
	ctx := context.Background()
	ct, err := a.Encrypt(b.Id, []byte("hello dispatch"))
	if err != nil {
		t.Fatal(err)
	}
	deps := OpenDeps(b)
	ev, err := DispatchFrame(ctx, b, b.IdentityPrivate, frame.Wrap(relay.TypeMessage, ct), deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != "message" || ev.Sender != a.Id || ev.Message != "hello dispatch" {
		t.Fatalf("bad event: %+v", ev)
	}
	if threads := deps.Mailbox.List(); len(threads) == 0 {
		t.Fatal("message must persist to mailbox")
	}
}

func TestDispatchOfferAnswer(t *testing.T) {
	a, b := twoClients(t)
	ctx := context.Background()
	// Fresh handshake through dispatch: A offers, B auto-answers via Sender.
	offer, err := a.CreateOffer(b.Id)
	if err != nil {
		t.Fatal(err)
	}
	var sent [][]byte
	sender := func(ctx context.Context, pub []byte, typ relay.Type, payload []byte) error {
		sent = append(sent, frame.Wrap(typ, payload))
		return nil
	}
	ev, err := DispatchFrame(ctx, b, b.IdentityPrivate, frame.Wrap(relay.TypeOffer, offer), OpenDeps(b), sender)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != "offer" || len(ev.Actions) != 1 || ev.Actions[0].Type != "answer_sent" {
		t.Fatalf("bad offer event: %+v", ev)
	}
	if len(sent) != 1 {
		t.Fatal("answer must be sent")
	}
	// A finishes on the dispatched answer.
	ev2, err := DispatchFrame(ctx, a, a.IdentityPrivate, sent[0], OpenDeps(a), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Type != "answer" {
		t.Fatalf("bad answer event: %+v", ev2)
	}
}

func TestDispatchBatchErrors(t *testing.T) {
	a, b := twoClients(t)
	ctx := context.Background()
	ct, _ := a.Encrypt(b.Id, []byte("x"))
	frames := [][]byte{
		frame.Wrap(relay.TypeMessage, ct),
		{0xFF},          // unknown type
		[]byte{},        // empty
		frame.Wrap(relay.TypeMessage, ct), // replay (same nonce) → error event
	}
	events := DispatchBatch(ctx, b, b.IdentityPrivate, frames, OpenDeps(b), nil)
	if len(events) != 4 {
		t.Fatalf("want 4 events, got %d", len(events))
	}
	if events[0].Type != "message" || events[1].Type != "error" || events[2].Type != "error" || events[3].Type != "error" {
		t.Fatalf("bad batch: %+v", events)
	}
}
