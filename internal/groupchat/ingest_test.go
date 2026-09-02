package groupchat

import (
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
)

// TestIngestDuplicateIsNotAnError pins the operator-facing behavior: feeding
// the same container twice succeeds once, then reports Kind "duplicate"
// instead of surfacing a scary replay/duplicate error.
func TestIngestDuplicateIsNotAnError(t *testing.T) {
	chdirTemp(t)
	alice, bob := handshakePair(t)

	if err := RunContext(alice.Id, []string{"create", "Dup Crew"}); err != nil {
		t.Fatal(err)
	}
	ctxs := mustListContexts(t, alice.Id)
	ctxID := string(ctxs[0].ContextID)
	if err := RunContext(alice.Id, []string{"add", ctxID, bob.Id}); err != nil {
		t.Fatal(err)
	}

	// Capture one exported container from a relay-less fan-out.
	outDir := t.TempDir()
	var container []byte
	out := captureStdoutGroup(t, func() {
		err := RunSendMulti(SendMultiRequest{
			LocalPeer:     alice.Id,
			CtxRef:        ctxID,
			Message:       "once only",
			InputEncoding: "raw",
			OutputDir:     outDir,
		})
		if err != nil {
			t.Errorf("send-multi: %v", err)
		}
	})
	_ = out
	entries := dirEntries(t, outDir)
	if len(entries) == 0 {
		t.Fatal("no container exported")
	}
	container = readFile(t, entries[0])

	bobStore, err := mailbox.Load(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	ctxStore, deliveryStore, err := multimsg.OpenIdentityStores(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	fan := multimsg.NewFanout(bob, nil, ctxStore, deliveryStore, multimsg.DefaultFanoutConfig())

	ev1, err := Ingest(bob, bobStore, fan, container)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if ev1.Kind != "group_message" || ev1.Message != "once only" {
		t.Fatalf("first ingest event: %+v", ev1)
	}

	ev2, err := Ingest(bob, bobStore, fan, container)
	if err != nil {
		t.Fatalf("duplicate ingest returned error: %v", err)
	}
	if ev2.Kind != "duplicate" {
		t.Fatalf("second ingest kind = %q, want duplicate", ev2.Kind)
	}

	// The thread must still contain exactly one copy.
	key, err := bobStore.ResolveThread("Dup Crew")
	if err != nil {
		t.Fatal(err)
	}
	msgs, _ := bobStore.Read(key)
	if len(msgs) != 1 {
		t.Fatalf("thread has %d messages after dup ingest, want 1", len(msgs))
	}

	// And a plain DM through the same standard path still works. Alice is
	// reloaded from disk first — the fan-out above persisted an advanced
	// ratchet, exactly as a second process would see it.
	freshAlice, err := Client.LoadClient(alice.Id)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := freshAlice.Encrypt(bob.Id, []byte("dm hi"))
	if err != nil {
		t.Fatal(err)
	}
	ev3, err := Ingest(bob, nil, fan, frame.Wrap(frame.TypeMessage, cipher))
	if err != nil || ev3.Kind != "message" || ev3.Sender != alice.Id {
		t.Fatalf("dm ingest = %+v, %v", ev3, err)
	}
}
