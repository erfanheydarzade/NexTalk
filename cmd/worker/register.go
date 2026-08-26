// cmd/worker/register.go
package worker

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
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
			t, data, err := workerrelay.UnwrapEnvelope(m.Body)
			if err != nil {
				continue
			}
			dispatchGUI(state, t, data)
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

func dispatchGUI(state *registry.State, t relay.Type, data []byte) {
	switch t {

	case relay.TypeOffer:
		offer, err := core.DecodeOffer(data)
		if err != nil {
			ui.Errorf("Bad offer payload: %v", err)
			return
		}
		ansBytes, err := state.ActiveClient.AcceptOffer(data)
		if err != nil {
			ui.Errorf("Accept offer failed: %v", err)
			return
		}
		pub, err := ed25519PubFromID(offer.SenderId)
		if err != nil {
			ui.Errorf("Invalid sender ID: %v", err)
			return
		}
		if err := sendEnvelope(state.Ctx, state.Worker, state.ActiveClient.IdentityPrivate, pub, relay.TypeAnswer, ansBytes); err != nil {
			ui.Errorf("Send answer failed: %v", err)
			return
		}
		state.RememberPeer(offer.SenderId)
		ui.Successf("Auto-answered offer from %s", registry.ShortID(offer.SenderId))
		ui.Infof("%s is now Tab-completable — try 'send <Tab>'.", registry.ShortID(offer.SenderId))

	case relay.TypeAnswer:
		peerID, err := state.ActiveClient.FinishHandshake(data)
		if err != nil {
			ui.Errorf("Handshake finish failed: %v", err)
			return
		}
		state.RememberPeer(peerID)
		ui.Successf("Session established with: %s", registry.ShortID(peerID))

	case relay.TypeMessage:
		senderID, pt, err := state.ActiveClient.Decrypt(data)
		if err != nil {
			ui.Errorf("Decrypt failed: %s", describeDecryptError(err))
			return
		}
		body := decodePlaintext(pt)
		if state.MailboxStore == nil {
			state.InitMailbox()
		}
		if state.MailboxStore != nil {
			if err := state.MailboxStore.AppendIncoming(senderID, body); err != nil {
				ui.Warnf("Received, but could not store: %v", err)
			}
		}
		state.RememberPeer(senderID)
		ui.Mailf("New message from %s — type 'mailbox %s'.", registry.ShortID(senderID), registry.ShortID(senderID))

	case relay.TypeMultiMsg:
		if state.Fanout == nil {
			ui.Warnf("Multi-message received but fanout not initialized")
			return
		}
		inbound, err := state.Fanout.ProcessDelivery(state.ActiveClient.Id, data)
		if err != nil {
			if errors.Is(err, multimsg.ErrDuplicateDelivery) {
				return // Already shown — stay silent on redelivery
			}
			ui.Errorf("Group message %s", describeDecryptError(err))
			return
		}
		if state.MailboxStore == nil {
			state.InitMailbox()
		}
		if state.MailboxStore != nil {
			err := state.MailboxStore.AppendGroupIncoming(
				string(inbound.ContextID()),
				inbound.DisplayName(),
				inbound.Sender,
				decodePlaintext(inbound.Plaintext),
			)
			if err != nil {
				ui.Warnf("Received, but could not store: %v", err)
			}
		}
		state.RememberPeer(inbound.Sender)
		// The hint must be something `mailbox <arg>` can actually resolve:
		// the display name when known, otherwise the short context ID
		// (ResolveThread matches unambiguous ID prefixes).
		groupName := inbound.DisplayName()
		hint := groupName
		if short, ok := strings.CutPrefix(groupName, "group:"); ok {
			hint = short
		}
		ui.Mailf("New group message in [%s] from %s — type 'mailbox %s'.",
			groupName, registry.ShortID(inbound.Sender), hint)

	default:
		ui.Warnf("Unknown envelope type: %d", t)
	}
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
