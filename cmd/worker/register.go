// cmd/worker/register.go
package worker

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	dispatchPkg "github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
	"github.com/spf13/cobra"
)

// ── Self-registration ─────────────────────────────────────────────────────────

func init() {
	registry.Register(registry.Entry{
		GUI:       &WorkerGUITransport{},
		CLI:       &workerCLITransport{},
		MenuOrder: 2,
	})
}

// ── CLI face ──────────────────────────────────────────────────────────────────

type workerCLITransport struct{}

func (w *workerCLITransport) RegisterCLI(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
	Register(parent, engine, cfg) // existing package-level Register in command.go
}

// ── GUI face ──────────────────────────────────────────────────────────────────
// WorkerGUITransport implements registry.GUITransport directly against
// registry.State — no intermediate RuntimeState or WorkerTransport needed.

type WorkerGUITransport struct{}

func (t *WorkerGUITransport) Name() string      { return "worker" }
func (t *WorkerGUITransport) MenuLabel() string { return "Worker Mode   (Cloud Relay)" }

// Commands implements registry.CompletionProvider. This is the single source
// of truth for both Tab completion and Help() — declaring a command here is
// what makes it completable, and the ArgKind of each slot is what decides
// whether Tab offers peer IDs, local identities, or nothing at all.
func (t *WorkerGUITransport) Commands() []registry.CommandSpec {
	specs := []registry.CommandSpec{
		{
			Name: "init",
			Help: "Generate a new identity & register with the relay",
		},
		registry.IdentityCommand("Load an existing local identity (Tab lists ./<id>.json files)"),
		{
			Name:  "connect",
			Args:  []registry.ArgKind{registry.ArgPeer},
			Usage: "connect <peer>",
			Help:  "Initiate a handshake (Tab completes peers/contacts; prefix ok)",
		},
		{
			Name: "listen",
			Help: "Poll the inbox & process offers/answers/messages",
		},
		func() registry.CommandSpec {
			s := registry.MessageCommand("send", "encrypt")
			s.Help = "Encrypt and dispatch a message"
			return s
		}(),
		// Group-chat surface comes from the shared standard implementation.
		registry.PeersCommand(),
	}
	return append(append(specs, groupchat.Specs()...), registry.BaseCommands()...)
}

func (t *WorkerGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n%s\n\n", ui.Header.Sprint("❖ Worker Mode Engaged (Cloud Relay) ❖"))

	if state.Worker == nil {
		w, err := workerrelay.New(state.Config.WorkerURL)
		if err != nil {
			return fmt.Errorf("worker init failed: %w", err)
		}
		state.Worker = w
	}

	state.InitMailbox()
	state.InitFanout()
	return nil
}

func (t *WorkerGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
	// Group-chat surface (context / send-multi / contexts / mailbox) is the
	// shared standard implementation — identical in every transport.
	if groupchat.Handles(cmd) {
		if cmd != "mailbox" && (state.ActiveClient == nil || state.Fanout == nil) {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		return groupchat.Execute(state, cmd, args)
	}

	switch cmd {

	case "init":
		state.ActiveClient = Client.NewClient()
		fmt.Printf("  %s Identity: %s\n", ui.Success.Sprint("[✓]"), ui.Bold.Sprint(state.ActiveClient.Id))

		pubHex, err := state.Worker.Register(state.Ctx, state.ActiveClient.IdentityPrivate)
		if err != nil {
			ui.Errorf("Registration failed: %v", err)
		} else if pubHex != hex.EncodeToString(state.ActiveClient.IdentityPublic) {
			ui.Warnf("Identity mismatch local=%s worker=%s",
				registry.ShortID(hex.EncodeToString(state.ActiveClient.IdentityPublic)), registry.ShortID(pubHex))
		} else {
			ui.Infof("Registered with relay server.")
		}

		state.InitMailbox()
		state.InitFanout()

	case "load":
		if len(args) < 1 {
			fmt.Println("  Usage: load <id>")
			return true
		}
		cl, err := Client.LoadClient(args[0])
		if err != nil {
			ui.Errorf("Load failed: %v", err)
			return true
		}
		state.ActiveClient = cl
		ui.Successf("Loaded: %s", cl.Id)

		state.SyncPeersFromClient()

		if _, err := state.Worker.Register(state.Ctx, cl.IdentityPrivate); err != nil {
			ui.Errorf("Re-registration failed: %v", err)
		} else {
			ui.Infof("Re-registered with relay server.")
		}

		state.InitMailbox()
		state.InitFanout()

	case "connect":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if len(args) < 1 {
			fmt.Println("  Usage: connect <peer>")
			return true
		}
		peerID, err := state.ResolvePeer(args[0])
		if err != nil {
			ui.Errorf("%v", err)
			return true
		}

		offerBytes, err := state.ActiveClient.CreateOffer(peerID)
		if err != nil {
			ui.Errorf("Offer creation failed: %v", err)
			return true
		}

		pub, err := ed25519PubFromID(peerID)
		if err != nil {
			ui.Errorf("Invalid peer ID: %v", err)
			return true
		}

		if err := sendEnvelope(state.Ctx, state.Worker, state.ActiveClient.IdentityPrivate, pub, relay.TypeOffer, offerBytes); err != nil {
			ui.Errorf("Send failed: %v", err)
			return true
		}

		state.RememberPeer(peerID)
		ui.Successf("Offer sent to %s", registry.ShortID(peerID))

	case "listen":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

		msgs, err := state.Worker.Receive(state.Ctx, state.ActiveClient.IdentityPrivate)
		if err != nil {
			ui.Errorf("Receive failed: %v", err)
			return true
		}
		if len(msgs) == 0 {
			ui.Infof("Inbox is empty.")
			return true
		}

		for _, m := range msgs {
			dispatchGUIFrame(state, m.Body)
		}

	case "send", "encrypt":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if len(args) < 2 {
			fmt.Println("  Usage: send <peer> <msg>")
			return true
		}
		peer, err := state.ResolvePeer(args[0])
		if err != nil {
			ui.Errorf("%v", err)
			return true
		}
		message := strings.Join(args[1:], " ")

		plaintext, err := readInput(message)
		if err != nil {
			ui.Errorf("%v", err)
			return true
		}

		cipherBytes, err := state.ActiveClient.Encrypt(peer, plaintext)
		if err != nil {
			ui.Errorf("Encryption failed: %v", err)
			return true
		}

		pub, err := ed25519PubFromID(peer)
		if err != nil {
			ui.Errorf("Invalid peer ID: %v", err)
			return true
		}

		if err := sendEnvelope(state.Ctx, state.Worker, state.ActiveClient.IdentityPrivate, pub, relay.TypeMessage, cipherBytes); err != nil {
			ui.Errorf("Send failed: %v", err)
			return true
		}

		if state.MailboxStore == nil {
			state.InitMailbox()
		}
		if state.MailboxStore == nil {
			ui.Errorf("Mailbox unavailable — re-run 'init' or 'load'.")
			return true
		}
		if err := state.MailboxStore.AppendOutgoing(peer, message); err != nil {
			ui.Warnf("Message sent but not recorded locally: %v", err)
		}
		state.RememberPeer(peer)
		ui.Successf("Message sent to %s", registry.ShortID(peer))

	case "peers":
		state.PrintPeers("'connect <id>' or 'listen'")

	case "help":
		t.Help()

	case "switch", "exit":
		return false

	default:
		ui.Errorf("Unknown command. Type 'help'.")
	}
	return true
}

func (t *WorkerGUITransport) Help() {
	registry.RenderHelp(t.Commands())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// dispatchGUIFrame routes one raw layer-1 frame through the shared,
// transport-agnostic dispatcher and renders the resulting event with the
// same UI text the worker shell always printed. Replies go back over the
// worker relay — the only worker-specific part left here.
func dispatchGUIFrame(state *registry.State, body []byte) {
	if state.ActiveClient == nil {
		return
	}
	sender := func(ctx context.Context, recipientPub []byte, t relay.Type, payload []byte) error {
		return sendEnvelope(ctx, state.Worker, state.ActiveClient.IdentityPrivate, recipientPub, t, payload)
	}
	d := &dispatchPkg.Deps{
		Client:  state.ActiveClient,
		Mailbox: state.MailboxStore,
		Fanout:  state.Fanout,
	}
	ev, err := dispatchPkg.DispatchFrame(state.Ctx, state.ActiveClient, state.ActiveClient.IdentityPrivate, body, d, sender)
	if err != nil {
		ui.Errorf("%v", err)
		return
	}
	if ev == nil {
		return // duplicate delivery, already shown
	}
	switch ev.Type {
	case "offer":
		state.RememberPeer(ev.Peer)
		ui.Successf("Auto-answered offer from %s", registry.ShortID(ev.Peer))
		ui.Infof("%s is now Tab-completable — try 'send <Tab>'.", registry.ShortID(ev.Peer))
	case "answer":
		state.RememberPeer(ev.Peer)
		ui.Successf("Session established with: %s", registry.ShortID(ev.Peer))
	case "message":
		state.RememberPeer(ev.Sender)
		ui.Mailf("New message from %s — type 'mailbox %s'.", registry.ShortID(ev.Sender), registry.ShortID(ev.Sender))
	case "group_message":
		state.RememberPeer(ev.Sender)
		hint := ev.Context
		if short, ok := strings.CutPrefix(ev.Context, "group:"); ok {
			hint = short
		}
		ui.Mailf("New group message in [%s] from %s — type 'mailbox %s'.",
			ev.Context, registry.ShortID(ev.Sender), hint)
	default:
		ui.Warnf("Unknown envelope type: %s", ev.Type)
	}
}

// dispatchGUI is kept for call-site stability and delegates to dispatchGUIFrame.
func dispatchGUI(state *registry.State, t relay.Type, data []byte) {
	dispatchGUIFrame(state, relay.WrapEnvelope(t, data))
}

// decodePlaintext renders raw decrypted bytes as displayable text. UTF-8 is
// shown verbatim; anything else falls back to base64 so binary payloads are
// never mangled into garbage.
func decodePlaintext(pt []byte) string {
	if utf8.Valid(pt) {
		return string(pt)
	}
	return base64.StdEncoding.EncodeToString(pt)
}
