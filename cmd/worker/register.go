// cmd/worker/register.go
package worker

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
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
		{
			Name:  "mailbox",
			Args:  []registry.ArgKind{registry.ArgPeer},
			Usage: "mailbox [peer]",
			Help:  "List chats, or read one peer's messages",
		},
		registry.PeersCommand(),
	}
	return append(specs, registry.BaseCommands()...)
}

func (t *WorkerGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n\033[1m\033[34m❖ Worker Mode Engaged (Cloud Relay) ❖\033[0m\n\n")

	if state.Worker == nil {
		w, err := workerrelay.New(state.Config.WorkerURL)
		if err != nil {
			return fmt.Errorf("worker init failed: %w", err)
		}
		state.Worker = w
	}

	if state.Mailbox == nil {
		state.Mailbox = make(map[string][]registry.ChatMessage)
	}
	return nil
}

func (t *WorkerGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
	switch cmd {

	case "init":
		state.ActiveClient = Client.NewClient()
		fmt.Printf("\033[32m  [✓]\033[0m Identity: \033[1m%s\033[0m\n", state.ActiveClient.Id)

		pubHex, err := state.Worker.Register(state.Ctx, state.ActiveClient.IdentityPrivate)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Registration failed: %v\n", err)
		} else if pubHex != hex.EncodeToString(state.ActiveClient.IdentityPublic) {
			fmt.Printf("\033[33m  [!]\033[0m Identity mismatch local=%s worker=%s\n",
				registry.ShortID(hex.EncodeToString(state.ActiveClient.IdentityPublic)), registry.ShortID(pubHex))
		} else {
			fmt.Printf("\033[36m  [i]\033[0m Registered with relay server.\n")
		}

	case "load":
		if len(args) < 1 {
			fmt.Println("  Usage: load <id>")
			return true
		}
		cl, err := Client.LoadClient(args[0])
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Load failed: %v\n", err)
			return true
		}
		state.ActiveClient = cl
		fmt.Printf("\033[32m  [✓]\033[0m Loaded: %s\n", cl.Id)

		// Sessions persisted in <id>.json become completable straight away,
		// so peers from a previous run don't have to be retyped.
		state.SyncPeersFromClient()

		if _, err := state.Worker.Register(state.Ctx, cl.IdentityPrivate); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Re-registration failed: %v\n", err)
		} else {
			fmt.Printf("\033[36m  [i]\033[0m Re-registered with relay server.\n")
		}

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
			fmt.Printf("\033[31m  [✗]\033[0m %v\n", err)
			return true
		}

		offerBytes, err := state.ActiveClient.CreateOffer(peerID)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Offer creation failed: %v\n", err)
			return true
		}

		pub, err := ed25519PubFromID(peerID)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid peer ID: %v\n", err)
			return true
		}

		if err := sendEnvelope(state.Ctx, state.Worker, state.ActiveClient.IdentityPrivate, pub, relay.TypeOffer, offerBytes); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Send failed: %v\n", err)
			return true
		}

		// Record the peer as soon as the offer is out. This is the fix for
		// the original bug: the initiator can now Tab-complete this ID for
		// send/mailbox/connect without waiting for a reply to create a
		// mailbox entry.
		state.RememberPeer(peerID)
		fmt.Printf("\033[32m  [✓]\033[0m Offer sent to %s\n", registry.ShortID(peerID))

	case "listen":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

		msgs, err := state.Worker.Receive(state.Ctx, state.ActiveClient.IdentityPrivate)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Receive failed: %v\n", err)
			return true
		}
		if len(msgs) == 0 {
			fmt.Printf("\033[36m  [i]\033[0m Inbox is empty.\n")
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
			fmt.Printf("\033[31m  [✗]\033[0m %v\n", err)
			return true
		}
		message := strings.Join(args[1:], " ")

		plaintext, err := readInput(message)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m %v\n", err)
			return true
		}

		cipherBytes, err := state.ActiveClient.Encrypt(peer, plaintext)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Encryption failed: %v\n", err)
			return true
		}

		pub, err := ed25519PubFromID(peer)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid peer ID: %v\n", err)
			return true
		}

		if err := sendEnvelope(state.Ctx, state.Worker, state.ActiveClient.IdentityPrivate, pub, relay.TypeMessage, cipherBytes); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Send failed: %v\n", err)
			return true
		}

		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}
		state.Mailbox[peer] = append(
			[]registry.ChatMessage{{Body: "Me: " + message, IsRead: true}},
			state.Mailbox[peer]...,
		)
		state.RememberPeer(peer)
		fmt.Printf("\033[32m  [✓]\033[0m Message sent to %s\n", registry.ShortID(peer))

	case "peers":
		state.PrintPeers("'connect <id>' or 'listen'")

	case "mailbox":
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}

		if len(args) == 0 {
			if len(state.Mailbox) == 0 {
				fmt.Printf("\033[36m  [i]\033[0m Mailbox is empty.\n")
				return true
			}
			fmt.Printf("\n\033[1m❖ Mailboxes ❖\033[0m\n")
			for peer, msgs := range state.Mailbox {
				unread := 0
				for _, m := range msgs {
					if !m.IsRead {
						unread++
					}
				}
				indicator := ""
				if unread > 0 {
					indicator = fmt.Sprintf("\033[33m [%d unread]\033[0m", unread)
				}
				fmt.Printf("  \033[36m%s\033[0m%s\n", registry.ShortID(peer), indicator)
			}
			fmt.Println("\nType 'mailbox <peer_id>' to read (Tab completes).")
			return true
		}

		// ResolvePeer replaces the old "first HasPrefix wins" loop, which
		// could silently pick the wrong peer when two IDs shared a prefix
		// (map iteration order is random, so it wasn't even deterministic).
		// Ambiguous prefixes now error out instead of guessing.
		fullPeer, err := state.ResolvePeer(args[0])
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m %v\n", err)
			return true
		}

		msgs, ok := state.Mailbox[fullPeer]
		if !ok {
			fmt.Printf("\033[33m  [!]\033[0m No messages from %s\n", registry.ShortID(fullPeer))
			return true
		}

		fmt.Printf("\n\033[1m❖ Messages with %s ❖\033[0m\n", registry.ShortID(fullPeer))
		for i, m := range msgs {
			mark := " "
			if !m.IsRead {
				mark = "\033[33m*\033[0m"
				state.Mailbox[fullPeer][i].IsRead = true
			}
			fmt.Printf("  [%s] %s\n", mark, m.Body)
		}
		fmt.Println()

	case "help":
		t.Help()

	case "switch", "exit":
		return false

	default:
		fmt.Printf("\033[31m  [✗]\033[0m Unknown command. Type 'help'.\n")
	}
	return true
}

func (t *WorkerGUITransport) Help() {
	// Rendered from the same specs that drive Tab completion, so the two can
	// never disagree about what exists.
	registry.RenderHelp(t.Commands())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// dispatchGUI routes a decoded (type, data) envelope pair and updates state in place.
//
// Every branch calls state.RememberPeer so the peer becomes Tab-completable
// the moment it is seen. This is the responder-side half of the completion
// bug: user B runs `listen`, receives an offer from user A, and previously had
// no way to Tab-complete A's ID afterwards because no mailbox entry existed
// until A sent an actual message.
func dispatchGUI(state *registry.State, t relay.Type, data []byte) {
	switch t {

	case relay.TypeOffer:
		var offer core.HandShakeOffer
		if err := json.Unmarshal(data, &offer); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Bad offer payload: %v\n", err)
			return
		}
		ansBytes, err := state.ActiveClient.AcceptOffer(data)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Accept offer failed: %v\n", err)
			return
		}
		pub, err := ed25519PubFromID(offer.SenderId)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid sender ID: %v\n", err)
			return
		}
		if err := sendEnvelope(state.Ctx, state.Worker, state.ActiveClient.IdentityPrivate, pub, relay.TypeAnswer, ansBytes); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Send answer failed: %v\n", err)
			return
		}
		state.RememberPeer(offer.SenderId)
		fmt.Printf("\033[32m  [✓]\033[0m Auto-answered offer from %s\n", registry.ShortID(offer.SenderId))
		fmt.Printf("\033[36m  [i]\033[0m %s is now Tab-completable — try 'send <Tab>'.\n", registry.ShortID(offer.SenderId))

	case relay.TypeAnswer:
		peerID, err := state.ActiveClient.FinishHandshake(data)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Handshake finish failed: %v\n", err)
			return
		}
		state.RememberPeer(peerID)
		fmt.Printf("\033[32m  [✓]\033[0m Session established with: %s\n", registry.ShortID(peerID))

	case relay.TypeMessage:
		senderID, pt, err := state.ActiveClient.Decrypt(data)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Decrypt failed: %v\n", err)
			return
		}
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}
		state.Mailbox[senderID] = append(
			[]registry.ChatMessage{{Body: string(pt), IsRead: false}},
			state.Mailbox[senderID]...,
		)
		state.RememberPeer(senderID)
		fmt.Printf("\033[35m  [✉]\033[0m New message from %s — check 'mailbox'.\n", registry.ShortID(senderID))

	default:
		fmt.Printf("\033[33m  [!]\033[0m Unknown envelope type: %d\n", t)
	}
}
