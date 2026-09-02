package worker

import (
	"context"
	"strings"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// sendOffer replicates what the interactive shell / `worker connect` does:
// CreateOffer produces NANOPACK BINARY (not JSON) which is framed with a
// 0x01 type byte and delivered via Relay.Send.
func sendOffer(t *testing.T, from *Client.Client, toID string, r *queueRelay) {
	t.Helper()
	offer, err := from.CreateOffer(toID)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ed25519PubFromID(toID)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(context.Background(), pub, relay.WrapEnvelope(relay.TypeOffer, offer), from.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
}

// Regression test for the reported bug:
//
//	listen
//	  [✗] Bad offer payload: invalid character '\x01' looking for beginning of value
//
// Offers moved to nanopack binary on the wire (core.Engine.CreateOffer returns
// MarshalFastID bytes). The dispatch layer must decode both encodings instead
// of json.Unmarshal-ing raw binary. This exercises the one-shot CLI listen.
func TestListenAutoAnswersNanopackOffer(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()

	alice := Client.NewClient()
	bob := Client.NewClient()
	ctx := context.Background()
	if _, err := r.Register(ctx, alice.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, bob.IdentityPrivate); err != nil {
		t.Fatal(err)
	}

	sendOffer(t, alice, bob.Id, r)

	c := &Command{engine: core.NewEngine(), cfg: config.Config{}, testRelay: r}
	out := captureStdout(t, func() {
		if err := c.RunListen(ctx, bob.Id, formatHuman); err != nil {
			t.Fatalf("bob listen: %v", err)
		}
	})
	if !strings.Contains(out, "Offer received") || !strings.Contains(out, "answer sent") {
		t.Fatalf("bob listen did not auto-answer the binary offer:\n%s", out)
	}

	// Alice polls the answer and completes the handshake initiator-side.
	out = captureStdout(t, func() {
		if err := c.RunListen(ctx, alice.Id, formatHuman); err != nil {
			t.Fatalf("alice listen: %v", err)
		}
	})
	if !strings.Contains(out, "Session established with "+bob.Id) {
		t.Fatalf("alice did not establish session from answer:\n%s", out)
	}

	// One-shot commands are separate processes: reload alice so she sees
	// the session her listen just persisted.
	alice, err := Client.LoadClient(alice.Id)
	if err != nil {
		t.Fatal(err)
	}

	// The established session must actually work end to end.
	sendDirectMessage(t, alice, bob, r, "hello over binary handshake")
	out = captureStdout(t, func() {
		if err := c.RunListen(ctx, bob.Id, formatHuman); err != nil {
			t.Fatalf("bob listen #2: %v", err)
		}
	})
	if !strings.Contains(out, "hello over binary handshake") {
		t.Fatalf("post-handshake message missing from listen output:\n%s", out)
	}
}

// Same scenario as TestListenAutoAnswersNanopackOffer but driven through the
// interactive-shell transport Execute("listen") — the exact code path that
// produced "Bad offer payload" in the report.
func TestShellTransportListensNanopackOffer(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()

	alice := Client.NewClient()
	bob := Client.NewClient()
	ctx := context.Background()
	if _, err := r.Register(ctx, alice.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, bob.IdentityPrivate); err != nil {
		t.Fatal(err)
	}

	sendOffer(t, alice, bob.Id, r)

	state := registry.NewState(core.NewEngine(), config.Config{})
	state.Ctx = ctx
	state.ActiveClient = bob
	state.Worker = r
	state.InitMailbox()
	state.InitFanout()

	var transport WorkerGUITransport
	out := captureStdout(t, func() {
		if !transport.Execute(state, "listen", nil) {
			t.Error("listen should keep the shell alive")
		}
	})
	if strings.Contains(out, "Bad offer payload") {
		t.Fatalf("regression: %s", out)
	}
	if !strings.Contains(out, "Auto-answered offer from "+registry.ShortID(alice.Id)) {
		t.Fatalf("shell listen did not auto-answer:\n%s", out)
	}

	// Bob must now be Tab-completable on alice's side after she processes
	// the answer, and the session must carry traffic both ways.
	out = captureStdout(t, func() {
		state.ActiveClient = alice
		state.Worker = r
		state.InitMailbox()
		state.InitFanout()
		transport.Execute(state, "listen", nil)
	})
	if !strings.Contains(out, "Session established with: "+registry.ShortID(bob.Id)) {
		t.Fatalf("alice shell listen did not finish handshake:\n%s", out)
	}

	cipher, err := alice.Encrypt(bob.Id, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	bobPub, err := ed25519PubFromID(bob.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(ctx, bobPub, relay.WrapEnvelope(relay.TypeMessage, cipher), alice.IdentityPrivate); err != nil {
		t.Fatal(err)
	}

	state.ActiveClient = bob
	state.InitMailbox()
	state.InitFanout()
	out = captureStdout(t, func() {
		transport.Execute(state, "listen", nil)
	})
	if !strings.Contains(out, "New message from "+registry.ShortID(alice.Id)) {
		t.Fatalf("encrypted DM not surfaced by shell listen:\n%s", out)
	}
}

// Regression test for: "send <peer> <msg>" right after `init` printed
// "[?] Mailbox unavailable � re-run 'init' or 'load'." � the init case never
// bound the mailbox store (the load case did), so outgoing messages were
// delivered but not recorded.
func TestShellInitBindsMailboxForSend(t *testing.T) {
	chdirTemp(t)
	r := newQueueRelay()
	ctx := context.Background()

	// The remote peer we'll talk to.
	peer := Client.NewClient()
	if _, err := r.Register(ctx, peer.IdentityPrivate); err != nil {
		t.Fatal(err)
	}

	var transport WorkerGUITransport
	state := registry.NewState(core.NewEngine(), config.Config{})
	state.Worker = r

	out := captureStdout(t, func() {
		if !transport.Execute(state, "init", nil) {
			t.Error("init should keep the shell alive")
		}
	})
	if !strings.Contains(out, "Registered with relay server.") {
		t.Fatalf("init failed:\n%s", out)
	}
	cl := state.ActiveClient

	// Complete a handshake into cl's queue: offer out, answer back.
	offer, err := cl.CreateOffer(peer.Id)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ed25519PubFromID(peer.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(ctx, pub, relay.WrapEnvelope(relay.TypeOffer, offer), cl.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
	answer, err := peer.AcceptOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	selfPub, err := ed25519PubFromID(cl.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(ctx, selfPub, relay.WrapEnvelope(relay.TypeAnswer, answer), peer.IdentityPrivate); err != nil {
		t.Fatal(err)
	}

	out = captureStdout(t, func() {
		transport.Execute(state, "listen", nil)
	})
	if !strings.Contains(out, "Session established with: "+registry.ShortID(peer.Id)) {
		t.Fatalf("handshake did not complete:\n%s", out)
	}

	out = captureStdout(t, func() {
		transport.Execute(state, "send", []string{peer.Id, `"hi`})
	})
	if strings.Contains(out, "Mailbox unavailable") {
		t.Fatalf("regression: %s", out)
	}
	if !strings.Contains(out, "Message sent to "+registry.ShortID(peer.Id)) {
		t.Fatalf("send failed:\n%s", out)
	}

	store, err := mailbox.Load(cl.Id)
	if err != nil {
		t.Fatal(err)
	}
	thread, ok := store.Get(peer.Id)
	if !ok || len(thread.Messages) == 0 {
		t.Fatal("sent message was not recorded in the local mailbox")
	}
	if got := thread.Messages[len(thread.Messages)-1]; got.Body != `"hi` || !got.IsRead {
		t.Fatalf("unexpected recorded message: %+v", got)
	}
}
