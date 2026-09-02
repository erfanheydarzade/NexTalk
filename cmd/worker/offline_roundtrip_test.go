package worker

import (
	"strings"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
)

// TestOfflineMultiSendRoundTrip is the cross-transport standard proof:
// offline (no relay) fans out a group message and exports per-recipient
// transfer Containers; a peer pastes one into `decrypt` and the message
// lands in the shared mailbox under the named group — exactly like the
// relay path, byte-for-byte the same framing.
func TestOfflineMultiSendRoundTrip(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()
	alice, bob := establishedPair(t, r)

	// Alice creates a context with bob as member (persisted stores).
	if err := groupchat.RunContext(alice.Id, []string{"create", "Air Gap Crew"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	ctxStore, err := multimsg.NewFileContextStore(
		alice.Id+".contexts.json", alice.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	ctxs, _ := ctxStore.ListContexts()
	if len(ctxs) != 1 {
		t.Fatalf("context not persisted")
	}
	ctxID := string(ctxs[0].ContextID)

	if err := groupchat.RunContext(alice.Id, []string{"add", ctxID, bob.Id}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Offline send-multi: no Relay provider ⇒ containers are exported.
	out := captureStdout(t, func() {
		err := groupchat.RunSendMulti(groupchat.SendMultiRequest{
			LocalPeer:     alice.Id,
			CtxRef:        ctxID,
			Message:       "hello over the gap",
			InputEncoding: "raw",
			Format:        formatHuman,
			Relay:         nil, // offline: no live transport
		})
		if err != nil {
			t.Fatalf("send-multi: %v", err)
		}
	})
	if !strings.Contains(out, "DELIVER TO") || !strings.Contains(out, `"Type":"multimsg"`) {
		t.Fatalf("containers not exported:\n%s", out)
	}
	if !utf8Printable(out) {
		t.Fatalf("binary leaked into output:\n%s", out)
	}

	// Extract the container object addressed to bob.
	var container string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `{`) && strings.Contains(line, `"Type":"multimsg"`) {
			container = line
			break
		}
	}
	if container == "" {
		t.Fatal("no container found in export output")
	}

	// Sanity: the container decodes back to a 0x04 frame.
	dec, err := frame.DecodeContainer([]byte(container))
	if err != nil || dec.Type != frame.TypeMultiMsg {
		t.Fatalf("container round-trip failed: %v", err)
	}

	// Bob ingests it through the same entry point his decrypt command uses.
	bobStore, err := mailbox.Load(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	bobCtxStore, err := multimsg.NewFileContextStore(
		bob.Id+".contexts.json", bob.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	bobDeliveries, err := multimsg.NewFileDeliveryStore(bob.Id + ".deliveries.json")
	if err != nil {
		t.Fatal(err)
	}
	bobFan := multimsg.NewFanout(bob, nil, bobCtxStore, bobDeliveries, multimsg.DefaultFanoutConfig())

	ev, err := groupchat.Ingest(bob, bobStore, bobFan, []byte(container))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if ev.Kind != "group_message" || ev.Message != "hello over the gap" {
		t.Fatalf("ingest event wrong: %+v", ev)
	}
	if ev.Context != "Air Gap Crew" {
		t.Errorf("group name not learned from signed metadata: %q", ev.Context)
	}

	// …and it is readable from the persistent mailbox.
	key, err := bobStore.ResolveThread("Air Gap Crew")
	if err != nil {
		t.Fatalf("thread missing after ingest: %v", err)
	}
	msgs, _ := bobStore.Read(key)
	if len(msgs) == 0 || msgs[0].Sender != alice.Id {
		t.Fatalf("mailbox thread wrong: %+v", msgs)
	}
}

// compile-time guards that the shared surface stays reachable from tests of
// any transport package.
var (
	_ = Client.NewClient
	_ = groupchat.Handles
)
