package shell

import (
	"slices"
	"strings"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/cmd/offline"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

// TestHandshakeMakesPeersCompletable is the end-to-end regression test for the
// reported bug, driven through the real offline transport and real PQ crypto.
//
// It replays the exact scenario from the report:
//
//	A (initiator): offer <B_id>   → B must be completable for A
//	B (responder): accept <offer> → A must be completable for B
//	A:             finish <answer>
//	A:             encrypt to B by ID prefix
//
// Before the fix, completion read only State.Mailbox, which the offline
// transport never writes — so no peer was ever completable in offline mode, and
// in worker mode a peer appeared only after a full message round-trip.
//
// readline is not exercised here (see readline_test.go for that); this calls the
// completer directly, which is the same entry point readline uses.
func TestHandshakeMakesPeersCompletable(t *testing.T) {
	dirs := tempDirs(t, 2)
	dirA, dirB := dirs[0], dirs[1]

	tr := &offline.OfflineGUITransport{}

	newShell := func(dir string) (*registry.State, *shellCompleter) {
		chdir(t, dir)
		st := registry.NewState(nil, testConfig())
		if err := tr.Init(st); err != nil {
			t.Fatal(err)
		}
		return st, newShellCompleter(st, tr)
	}

	stateA, completerA := newShell(dirA)
	stateA.ActiveClient = Client.NewClient()
	idA := stateA.ActiveClient.Id

	stateB, completerB := newShell(dirB)
	stateB.ActiveClient = Client.NewClient()
	idB := stateB.ActiveClient.Id

	// Sanity: nothing completes before any handshake step.
	chdir(t, dirA)
	if got := complete(t, completerA, "encrypt "); len(got) != 0 {
		t.Fatalf("expected no peers before the handshake, got %v", got)
	}

	// Step 1 — A offers to B. THE BUG: B must now complete for A, with no
	// message exchanged and no mailbox entry in existence.
	offer := extractJSON(t, exec(t, tr, stateA, "offer", idB))
	assertCompletes(t, completerA, "encrypt "+idB[:6], idB, "after offer, A")

	// Step 2 — B accepts. THE OTHER HALF: B saw A only via an incoming offer.
	chdir(t, dirB)
	answer := extractJSON(t, execWithStdin(t, tr, stateB, offer+"\n", "accept"))
	assertCompletes(t, completerB, "encrypt "+idA[:6], idA, "after accept, B")

	// Step 3 — A finishes the handshake.
	chdir(t, dirA)
	execWithStdin(t, tr, stateA, answer+"\n", "finish")
	assertCompletes(t, completerA, "encrypt "+idB[:6], idB, "after finish, A")

	// Step 4 — A encrypts using a short prefix instead of the full ID, proving
	// completion and command-side resolution agree: what Tab offers, commands take.
	if out := exec(t, tr, stateA, "encrypt", idB[:6], "hello", "from", "A"); strings.Contains(out, "Encrypt failed") {
		t.Fatalf("encrypt with a peer prefix failed: %s", out)
	}

	// Step 5 — a restarted shell must still complete peers, since they live in
	// <id>.json's session map.
	stateB2, completerB2 := newShell(dirB)
	exec(t, tr, stateB2, "load", idB)
	assertCompletes(t, completerB2, "encrypt "+idA[:6], idA, "after reload, B")
}

// TestOfflineCompletionMatchesOfflineCommands guards the second half of the
// original bug: one hard-coded command list was shared by every transport, so
// offline mode completed `listen` (which it lacks) and not `offer`, `accept`,
// `finish` or `decrypt` (which it has).
func TestOfflineCompletionMatchesOfflineCommands(t *testing.T) {
	chdirTemp(t)

	tr := &offline.OfflineGUITransport{}
	all := complete(t, newShellCompleter(registry.NewState(nil, testConfig()), tr), "")

	for _, want := range []string{"init", "load", "offer", "accept", "finish", "encrypt", "decrypt", "help", "switch", "exit"} {
		if !slices.Contains(all, want) {
			t.Errorf("offline completion missing %q: %v", want, all)
		}
	}
	if slices.Contains(all, "listen") {
		t.Errorf("offline completion must not offer 'listen' (worker-only): %v", all)
	}
}

func assertCompletes(t *testing.T, c *shellCompleter, line, want, context string) {
	t.Helper()
	if got := complete(t, c, line); !slices.Contains(got, want) {
		t.Fatalf("%s cannot complete %q — completing %q gave %v", context, want, line, got)
	}
}
