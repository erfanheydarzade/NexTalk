// cmd/worker/register.go
package worker

import (
	"encoding/base64"
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
func (t *WorkerGUITransport) MenuLabel() string { return "2. Worker Mode   (Cloud Relay)" }

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
		state.ActiveClient = state.API.Initialize()
		fmt.Printf("\033[32m  [✓]\033[0m Identity: \033[1m%s\033[0m\n", state.ActiveClient.Id)

		pubHex, err := state.Worker.Register(state.Ctx, state.ActiveClient.IdentityPrivate)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Registration failed: %v\n", err)
		} else if pubHex != hex.EncodeToString(state.ActiveClient.IdentityPublic) {
			fmt.Printf("\033[33m  [!]\033[0m Identity mismatch local=%s worker=%s\n",
				shortID(hex.EncodeToString(state.ActiveClient.IdentityPublic)), shortID(pubHex))
		} else {
			fmt.Printf("\033[36m  [i]\033[0m Registered with relay server.\n")
		}

	case "load":
		if len(args) < 1 {
			fmt.Println("  Usage: load <id>")
			return true
		}
		cl, err := state.API.LoadClient(args[0])
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Load failed: %v\n", err)
			return true
		}
		state.ActiveClient = cl
		fmt.Printf("\033[32m  [✓]\033[0m Loaded: %s\n", cl.Id)

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
		peerID := args[0]

		offerBytes, err := state.API.CreateOffer(peerID)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Offer creation failed: %v\n", err)
			return true
		}

		pub, err := ed25519PubFromID(peerID)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid peer ID: %v\n", err)
			return true
		}

		env := relay.Envelope{Type: relay.TypeOffer, Data: json.RawMessage(offerBytes)}
		payload, _ := json.Marshal(env)
		if err := state.Worker.Send(state.Ctx, pub, payload, state.ActiveClient.IdentityPrivate); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Send failed: %v\n", err)
			return true
		}
		fmt.Printf("\033[32m  [✓]\033[0m Offer sent to %s\n", shortID(peerID))

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
			body := tryDecode(m.Body)
			var env relay.Envelope
			if err := json.Unmarshal(body, &env); err != nil {
				continue
			}
			dispatchGUI(state, env)
		}

	case "send", "encrypt":
		if len(args) < 2 {
			fmt.Println("  Usage: send <peer> <msg>")
			return true
		}
		peer := args[0]
		msg := strings.Join(args[1:], " ")

		cipherBytes, err := state.API.Encrypt(peer, msg)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Encryption failed: %v\n", err)
			return true
		}

		pub, err := ed25519PubFromID(peer)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid peer ID: %v\n", err)
			return true
		}

		env := relay.Envelope{Type: relay.TypeMessage, Data: json.RawMessage(cipherBytes)}
		payload, _ := json.Marshal(env)
		if err := state.Worker.Send(state.Ctx, pub, payload, state.ActiveClient.IdentityPrivate); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Send failed: %v\n", err)
			return true
		}

		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}
		state.Mailbox[peer] = append(
			[]registry.ChatMessage{{Body: "Me: " + msg, IsRead: true}},
			state.Mailbox[peer]...,
		)
		fmt.Printf("\033[32m  [✓]\033[0m Message sent to %s\n", shortID(peer))

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
				fmt.Printf("  \033[36m%s\033[0m%s\n", shortID(peer), indicator)
			}
			fmt.Println("\nType 'mailbox <peer_id>' to read.")
			return true
		}

		target := args[0]
		fullPeer := target
		for peer := range state.Mailbox {
			if strings.HasPrefix(peer, target) {
				fullPeer = peer
				break
			}
		}

		msgs, ok := state.Mailbox[fullPeer]
		if !ok {
			fmt.Printf("\033[33m  [!]\033[0m No messages from %s\n", target)
			return true
		}

		fmt.Printf("\n\033[1m❖ Messages with %s ❖\033[0m\n", shortID(fullPeer))
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
	fmt.Printf("\n\033[1mCommands:\033[0m\n")
	fmt.Println("  init                  - Generate new identity & register")
	fmt.Println("  load <id>             - Load existing identity")
	fmt.Println("  connect <peer>        - Initiate handshake with peer")
	fmt.Println("  listen                - Poll inbox & process events")
	fmt.Println("  send <peer> <msg>     - Encrypt and dispatch message")
	fmt.Println("  mailbox               - List all active chats/mailboxes")
	fmt.Println("  mailbox <peer>        - Read messages from a specific peer")
	fmt.Println("  switch / exit         - Return to main menu")
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func shortID(id string) string {
	if len(id) < 12 {
		return id
	}
	return id[:6] + "..." + id[len(id)-4:]
}

// dispatchGUI routes a decoded envelope and updates state in place.
func dispatchGUI(state *registry.State, env relay.Envelope) {
	switch env.Type {

	case relay.TypeOffer:
		var offer Client.HandshakeOffer
		if err := json.Unmarshal(env.Data, &offer); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Bad offer payload: %v\n", err)
			return
		}
		ansBytes, err := state.API.AcceptOffer(env.Data)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Accept offer failed: %v\n", err)
			return
		}
		pub, err := ed25519PubFromID(offer.SenderId)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid sender ID: %v\n", err)
			return
		}
		ansEnv := relay.Envelope{Type: relay.TypeAnswer, Data: json.RawMessage(ansBytes)}
		payload, _ := json.Marshal(ansEnv)
		if err := state.Worker.Send(state.Ctx, pub, payload, state.ActiveClient.IdentityPrivate); err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Send answer failed: %v\n", err)
			return
		}
		fmt.Printf("\033[32m  [✓]\033[0m Auto-answered offer from %s\n", shortID(offer.SenderId))

	case relay.TypeAnswer:
		peerID, err := state.API.FinishHandshake(env.Data)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Handshake finish failed: %v\n", err)
			return
		}
		fmt.Printf("\033[32m  [✓]\033[0m Session established with: %s\n", shortID(peerID))

	case relay.TypeMessage:
		senderID, pt, err := state.API.Decrypt(
			base64.StdEncoding.EncodeToString(env.Data),
		)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Decrypt failed: %v\n", err)
			return
		}
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}
		state.Mailbox[senderID] = append(
			[]registry.ChatMessage{{Body: pt, IsRead: false}},
			state.Mailbox[senderID]...,
		)
		fmt.Printf("\033[35m  [✉]\033[0m New message from %s — check 'mailbox'.\n", shortID(senderID))

	default:
		fmt.Printf("\033[33m  [!]\033[0m Unknown envelope type: %q\n", env.Type)
	}
}
