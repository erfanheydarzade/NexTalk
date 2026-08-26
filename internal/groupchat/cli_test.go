package groupchat

import (
	"strings"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
)

// chdirTemp keeps per-identity store files out of the repo directory.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, err := osGetwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := osChdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { osChdir(old) })
}

func TestRunContextNonexistentGivesActionableError(t *testing.T) {
	chdirTemp(t)
	cl := Client.NewClient()

	err := RunContext(cl.Id, []string{"add", "deadbeef", "somepeer"})
	if err == nil {
		t.Fatal("expected error for nonexistent context")
	}
	for _, want := range []string{`"deadbeef"`, "does not exist", "context create"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestContextAddRejectsInvalidPeerID(t *testing.T) {
	chdirTemp(t)
	cl := Client.NewClient()
	if err := RunContext(cl.Id, []string{"create", "Validators"}); err != nil {
		t.Fatal(err)
	}
	ctxs := mustListContexts(t, cl.Id)
	ctxID := string(ctxs[0].ContextID)

	err := RunContext(cl.Id, []string{"add", ctxID, "typo-peer"})
	if err == nil || !strings.Contains(err.Error(), "not a valid NexTalk peer ID") {
		t.Fatalf("invalid peer accepted: %v", err)
	}

	// A well-formed ID passes.
	good := base58Encode(make([]byte, 64))
	if err := RunContext(cl.Id, []string{"add", ctxID, good}); err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}

	// Re-adding the same member is idempotent (policy overwrite), not an error.
	if err := RunContext(cl.Id, []string{"add", ctxID, good}); err != nil {
		t.Fatalf("duplicate add should be idempotent: %v", err)
	}
}

func TestSendMultiEmptyGroupNamesContext(t *testing.T) {
	chdirTemp(t)
	cl := Client.NewClient()
	if err := RunContext(cl.Id, []string{"create", "Empty Crew"}); err != nil {
		t.Fatal(err)
	}
	err := RunSendMulti(SendMultiRequest{
		LocalPeer:     cl.Id,
		CtxRef:        "Empty Crew",
		Message:       "nobody hears this",
		InputEncoding: "raw",
	})
	if err == nil || !strings.Contains(err.Error(), "Empty Crew") {
		t.Fatalf("empty-group error = %v, want context name", err)
	}
}

func TestSendMultiExportsContainersToOutputDir(t *testing.T) {
	chdirTemp(t)
	alice, bob := handshakePair(t)

	if err := RunContext(alice.Id, []string{"create", "Dir Crew"}); err != nil {
		t.Fatal(err)
	}
	ctxs := mustListContexts(t, alice.Id)
	ctxID := string(ctxs[0].ContextID)
	if err := RunContext(alice.Id, []string{"add", ctxID, bob.Id}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir() + "/containers"
	out := captureStdoutGroup(t, func() {
		err := RunSendMulti(SendMultiRequest{
			LocalPeer:     alice.Id,
			CtxRef:        ctxID,
			Message:       "to the file",
			InputEncoding: "raw",
			OutputDir:     dir,
			Relay:         nil, // offline-style export
		})
		if err != nil {
			t.Errorf("send-multi: %v", err)
		}
	})

	entries := dirEntries(t, dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 exported container, got %d (%v)", len(entries), entries)
	}
	if !strings.Contains(out, "1 encrypted") {
		t.Errorf("summary should say 'encrypted' when nothing was transmitted:\n%s", out)
	}
	if strings.Contains(out, "1 sent") {
		t.Errorf("relay-less export must not claim messages were sent:\n%s", out)
	}

	// The exported file is a valid container that decodes to a 0x04 frame.
	data := readFile(t, entries[0])
	dec, err := frame.DecodeContainer(data)
	if err != nil || dec.Type != frame.TypeMultiMsg {
		t.Fatalf("exported container invalid: %v", err)
	}
}
