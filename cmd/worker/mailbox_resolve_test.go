package worker

import (
	"strings"
	"testing"

	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

func newResolverState(t *testing.T) *registry.State {
	t.Helper()
	return registry.NewState(nil, config.Config{})
}

// TestResolveThreadKeyGroupForms is the regression test for real-world
// session feedback: after `listen` prints "type 'mailbox group:f6b68fcb'",
// that exact argument (and its siblings) must resolve to the group thread.
// The old implementation asked ResolvePeer first, whose verbatim passthrough
// swallowed every group reference before mailbox lookup ever ran.
func TestResolveThreadKeyGroupForms(t *testing.T) {
	st := newResolverState(t)
	store, err := mailbox.Load("resolverIdentity")
	if err != nil {
		t.Fatal(err)
	}
	const ctxID = "f6b68fcb0000000000000000000000000000000000000000000000000000abcd"

	// Mirror what dispatchGUI records when the context is unknown:
	// display name falls back to "group:<short id>".
	if err := store.AppendGroupIncoming(ctxID, "group:f6b68fcb", "senderPeer", "hello"); err != nil {
		t.Fatal(err)
	}
	st.MailboxStore = store

	for _, arg := range []string{
		"group:f6b68fcb", // exactly what the notification suggests
		"ctx:" + ctxID,   // full key
		ctxID,            // bare full ID
		ctxID[:8],        // short ID prefix
		"group:f6b68fc",  // prefixed short
	} {
		got, err := groupchat.ResolveThreadKey(st, arg)
		if err != nil {
			t.Errorf("resolve(%q): %v", arg, err)
			continue
		}
		if got != mailbox.GroupKey(ctxID) {
			t.Errorf("resolve(%q) = %q, want %q", arg, got, mailbox.GroupKey(ctxID))
		}
	}
}

func TestResolveThreadKeyPeerPrecedence(t *testing.T) {
	st := newResolverState(t)
	store, err := mailbox.Load("resolverIdentity")
	if err != nil {
		t.Fatal(err)
	}

	// A DM thread for a peer...
	const peer = "someExistingPeerWithHistory1234567890abcdef"
	if err := store.AppendIncoming(peer, "dm hello"); err != nil {
		t.Fatal(err)
	}
	// ...and a group that shares nothing with it.
	if err := store.AppendGroupIncoming("aaaabbbbccccdddd", "Team", "x", "greeting"); err != nil {
		t.Fatal(err)
	}

	st.MailboxStore = store
	st.RememberPeer(peer)

	// Existing peer thread wins.
	got, err := groupchat.ResolveThreadKey(st, peer)
	if err != nil || got != peer {
		t.Errorf("peer resolution: key=%q err=%v", got, err)
	}

	// Group name resolves to the group.
	got, err = groupchat.ResolveThreadKey(st, "Team")
	if err != nil || got != mailbox.GroupKey("aaaabbbbccccdddd") {
		t.Errorf("group by name: key=%q err=%v", got, err)
	}

	// Verbatim brand-new peer passes through (no history yet).
	const fresh = "brandNewPeerNobodyMessagedYet0987654321"
	got, err = groupchat.ResolveThreadKey(st, fresh)
	if err != nil || got != fresh {
		t.Errorf("fresh peer passthrough: key=%q err=%v", got, err)
	}

	// Explicit group prefixes never fall back to peers.
	got, err = groupchat.ResolveThreadKey(st, "ctx:zzzz-not-here")
	if err == nil || !strings.Contains(err.Error(), "no conversation") {
		t.Errorf("missing explicit group ref: key=%q err=%v", got, err)
	}
}
