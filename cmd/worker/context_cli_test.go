package worker

import (
	"context"
	"strings"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// TestContextCLIFullWorkflow drives `worker context` end-to-end: create a
// group, add a member, list, rename, then send-multi through the relay and
// confirm the recipient's listen files it under the named group thread.
func TestContextCLIFullWorkflow(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()
	alice, bob := establishedPair(t, r)

	// create
	out := captureStdout(t, func() {
		if err := groupchat.RunContext(alice.Id, []string{"create", "CLI Crew"}); err != nil {
			t.Fatalf("create: %v", err)
		}
	})
	if !strings.Contains(out, "CLI Crew") {
		t.Errorf("create output missing name:\n%s", out)
	}

	// The persisted store is the source of truth for the rest of the flow.
	ctxStore, err := multimsg.NewJSONContextStore(
		alice.Id+".contexts.json", alice.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	ctxs, _ := ctxStore.ListContexts()
	if len(ctxs) != 1 || ctxs[0].DisplayName != "CLI Crew" {
		t.Fatalf("created context not persisted: %+v", ctxs)
	}
	ctxID := string(ctxs[0].ContextID)

	// add member
	out = captureStdout(t, func() {
		if err := groupchat.RunContext(alice.Id, []string{"add", ctxID, bob.Id}); err != nil {
			t.Fatalf("add: %v", err)
		}
	})
	if !strings.Contains(out, "enabled") {
		t.Errorf("add output unexpected:\n%s", out)
	}
	// The command wrote through its own store instance — reopen from disk
	// (exactly what another process would see).
	ctxStore, err = multimsg.NewJSONContextStore(
		alice.Id+".contexts.json", alice.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := ctxStore.LoadPolicy(multimsg.ContextID(ctxID), bob.Id)
	if err != nil || pol.Policy != multimsg.PolicyEnabled {
		t.Fatalf("policy not persisted: %v %+v", err, pol)
	}

	// mute then re-include
	captureStdout(t, func() { groupchat.RunContext(alice.Id, []string{"mute", ctxID, bob.Id}) })
	ctxStore, _ = multimsg.NewJSONContextStore(
		alice.Id+".contexts.json", alice.Id+".policies.json")
	pol, _ = ctxStore.LoadPolicy(multimsg.ContextID(ctxID), bob.Id)
	if pol.Policy != multimsg.PolicyMuted {
		t.Fatalf("mute did not persist: %+v", pol)
	}
	captureStdout(t, func() { groupchat.RunContext(alice.Id, []string{"include", ctxID, bob.Id}) })
	ctxStore, _ = multimsg.NewJSONContextStore(
		alice.Id+".contexts.json", alice.Id+".policies.json")
	pol, _ = ctxStore.LoadPolicy(multimsg.ContextID(ctxID), bob.Id)
	if pol.Policy != multimsg.PolicyEnabled {
		t.Fatalf("include did not restore enabled: %+v", pol)
	}

	// rename must succeed (regression: self-comparison rejected equal versions)
	out = captureStdout(t, func() {
		if err := groupchat.RunContext(alice.Id, []string{"rename", ctxID, "Renamed CLI Crew"}); err != nil {
			t.Fatalf("rename: %v", err)
		}
	})
	if !strings.Contains(out, "v2") {
		t.Errorf("rename output missing version bump:\n%s", out)
	}

	// members listing renders without error
	captureStdout(t, func() {
		if err := groupchat.RunContext(alice.Id, []string{"members", ctxID}); err != nil {
			t.Fatalf("members: %v", err)
		}
	})

	// send-multi through the relay
	out = captureStdout(t, func() {
		err := groupchat.RunSendMulti(groupchat.SendMultiRequest{
			LocalPeer:     alice.Id,
			CtxRef:        ctxID,
			Message:       "hello group",
			InputEncoding: "raw",
			Format:        formatHuman,
			Relay:         func() (relay.Relay, error) { return r, nil },
		})
		if err != nil {
			t.Fatalf("send-multi: %v", err)
		}
	})
	if !strings.Contains(out, "1 encrypted") {
		t.Errorf("send-multi summary unexpected:\n%s", out)
	}

	// Sender's mailbox records the outgoing group message.
	sent, err := mailbox.Load(alice.Id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sent.ResolveThread(ctxID)
	if err != nil {
		t.Fatalf("sender group thread missing: %v", err)
	}
	msgs, _ := sent.Read(key)
	foundOutgoing := false
	for _, m := range msgs {
		if m.Direction == mailbox.Outgoing && m.Body == "hello group" {
			foundOutgoing = true
		}
	}
	if !foundOutgoing {
		t.Errorf("outgoing group message not recorded:\n%+v", msgs)
	}

	// Recipient polls once and gets a group_message filed under the thread.
	rc := &Command{engine: core.NewEngine(), cfg: config.Config{}, testRelay: r}
	if err := rc.RunListen(context.Background(), bob.Id, formatHuman); err != nil {
		t.Fatalf("listen: %v", err)
	}
	received, err := mailbox.Load(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := received.ResolveThread("Renamed CLI Crew") // metadata learned from the wire
	if err != nil {
		t.Fatalf("recipient group thread missing: %v", err)
	}
	bobMsgs, err := received.Read(bobKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(bobMsgs) == 0 || bobMsgs[0].Body != "hello group" {
		t.Errorf("recipient thread wrong: %+v", bobMsgs)
	}
	if len(bobMsgs) > 0 && bobMsgs[0].Sender != alice.Id {
		t.Errorf("attribution wrong: %+v", bobMsgs[0])
	}
}

// TestContextCandidatesCompletion checks that CLI completion surfaces both
// context IDs and display names from the persisted store.
func TestContextCandidatesCompletion(t *testing.T) {
	chdirTemp(t)

	cl := Client.NewClient()
	store, err := multimsg.NewJSONContextStore(cl.Id+".contexts.json", cl.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	fan := multimsg.NewFanout(cl, nil, store, nil, multimsg.DefaultFanoutConfig())
	meta, err := fan.CreateContext("Completors", cl.IdentityPrivate)
	if err != nil {
		t.Fatal(err)
	}

	got := groupchat.ContextCandidates(cl.Id)
	wantID := string(meta.ContextID)
	okID, okName := false, false
	for _, g := range got {
		if g == wantID {
			okID = true
		}
		if g == "Completors" {
			okName = true
		}
	}
	if !okID || !okName {
		t.Errorf("context candidates = %v, want ID + display name", got)
	}

	// Unknown identity yields no candidates, never an error.
	if got := groupchat.ContextCandidates("nobody-here"); len(got) != 0 {
		t.Errorf("expected no candidates for unknown identity, got %v", got)
	}
}
