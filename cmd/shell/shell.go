package shell

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	"github.com/mr-tron/base58"
)

// --- ANSI Colors & UI Helpers ---
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Cyan    = "\033[36m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Red     = "\033[31m"
	Magenta = "\033[35m"
	Blue    = "\033[34m"
)
const (
	reset = "\033[0m"
	bold  = "\033[1m"
	cyan  = "\033[36m"
	green = "\033[32m"
	red   = "\033[31m"
)

func clearScreen() { fmt.Print("\033[H\033[2J") }

func printSuccess(msg string, args ...any) { fmt.Printf(Green+"  [✓] "+Reset+msg+"\n", args...) }
func printInfo(msg string, args ...any)    { fmt.Printf(Cyan+"  [i] "+Reset+msg+"\n", args...) }
func printWarning(msg string, args ...any) { fmt.Printf(Yellow+"  [!] "+Reset+msg+"\n", args...) }
func printError(msg string, args ...any)   { fmt.Printf(Red+"  [✗] "+Reset+msg+"\n", args...) }
func printMessage(msg string, args ...any) { fmt.Printf(Magenta+"  [✉] "+Reset+msg+"\n", args...) }

// shortID visually trims long keys (e.g., 911ef9...4f28)
func shortID(id string) string {
	if len(id) < 12 {
		return id
	}
	return id[:6] + "..." + id[len(id)-4:]
}

// ---------------------------------------------------------
// 1. Core Types & State
// ---------------------------------------------------------

type PayloadEnvelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type ChatMessage struct {
	Body   string
	IsRead bool
}

// RuntimeState.Worker is a relay.Relay — the SAME interface and SAME
// implementation (internal/relay/worker.Adapter) the CLI's `worker` command
// uses. There is deliberately no separate GUI-only HTTP client anymore: the
// previous transport/storage.Client duplicated Register/Send/Receive against
// the same worker API and silently drifted out of sync (it never got
// sender-authentication added to its Send when the worker started requiring
// it, which is what caused "sender.pubkey must be a 64-char..." errors here
// while the CLI worked fine). One implementation, one place sender-auth
// signing happens (relay.BuildSenderAuth), used by both.
type RuntimeState struct {
	API          *core.Engine
	ActiveClient *Client.Client
	Config       config.Config
	Worker       relay.Relay
	Ctx          context.Context
	Mailbox      map[string][]ChatMessage
}

type Transport interface {
	Name() string
	Init(state *RuntimeState) error
	Execute(state *RuntimeState, cmd string, args []string) (keepRunning bool)
	Help()
}

// ---------------------------------------------------------
// 2. Shared Helpers
// ---------------------------------------------------------

func tryDecode(b []byte) []byte {
	d, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return b
	}
	return d
}

func ed25519PubFromID(peerID string) ([]byte, error) {
	raw, err := base58.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("base58 decode: %w", err)
	}

	if len(raw) < 32 {
		return nil, fmt.Errorf(
			"invalid peer id length: %d",
			len(raw),
		)
	}

	return raw[:32], nil
}

// sendEnvelope marshals env and sends it through state.Worker. Sender-auth
// signing happens inside state.Worker.Send itself (over the exact bytes it
// puts on the wire, after any transport-level encoding) — this just passes
// the caller's identity private key through.
func sendEnvelope(
	state *RuntimeState,
	peerID string,
	env PayloadEnvelope,
) {
	pub, err := ed25519PubFromID(peerID)
	if err != nil {
		printError("Invalid peer ID: %v", err)
		return
	}

	if state.ActiveClient == nil {
		printError("No active identity — 'init' or 'load' first.")
		return
	}

	b, err := json.Marshal(env)
	if err != nil {
		printError("Marshal envelope failed: %v", err)
		return
	}

	if err := state.Worker.Send(state.Ctx, pub, b, state.ActiveClient.IdentityPrivate); err != nil {
		printError("Send failed: %v", err)
	}
}

// ---------------------------------------------------------
// 3. Worker Transport Implementation
// ---------------------------------------------------------

type WorkerTransport struct{}

func (t *WorkerTransport) Name() string { return "worker" }

func (t *WorkerTransport) Init(state *RuntimeState) error {
	clearScreen()
	fmt.Printf("%s%s❖ Worker Mode Engaged (Cloud Relay) ❖%s\n\n", Bold, Blue, Reset)
	if state.Worker == nil {
		w, err := workerrelay.New(state.Config.WorkerURL)
		if err != nil {
			return fmt.Errorf("worker init failed: %w", err)
		}
		state.Worker = w
	}

	if state.Mailbox == nil {
		state.Mailbox = make(map[string][]ChatMessage)
	}
	return nil
}

func (t *WorkerTransport) Execute(state *RuntimeState, cmd string, args []string) bool {
	switch cmd {
	case "init":
		state.ActiveClient = state.API.Initialize()
		printSuccess("Identity Initialized: %s%s%s", Bold, state.ActiveClient.Id, Reset)
		pubHex, err := state.Worker.Register(
			state.Ctx,
			state.ActiveClient.IdentityPrivate,
		)

		if err != nil {
			printError("Worker relay registration failed: %v", err)
		} else {
			expectedPubHex := hex.EncodeToString(
				state.ActiveClient.IdentityPublic,
			)

			if expectedPubHex != pubHex {
				printWarning(
					"Identity mismatch local=%s worker=%s",
					shortID(expectedPubHex),
					shortID(pubHex),
				)
			} else {
				printInfo("Registered with relay server.")
			}
		}

	case "load":
		if len(args) < 1 {
			printWarning("Usage: load <id>")
			return true
		}
		cl, err := state.API.LoadClient(args[0])
		if err != nil {
			printError("Load failed: %v", err)
			return true
		}
		state.ActiveClient = cl
		printSuccess("Loaded: %s", cl.Id)
		if _, err := state.Worker.Register(state.Ctx, cl.IdentityPrivate); err != nil {
			printError("Re-registration failed: %v", err)
		} else {
			printInfo("Re-registered with relay server.")
		}

	case "connect":
		if state.ActiveClient == nil || state.ActiveClient.Id == "" {
			printWarning("Please 'init' or 'load' an identity first.")
			return true
		}
		if len(args) < 1 {
			printWarning("Usage: connect <peer>")
			return true
		}
		peerID := args[0]
		offerBytes, err := state.API.CreateOffer(peerID)
		if err != nil {
			printError("Offer creation failed: %v", err)
			return true
		}
		env := PayloadEnvelope{Type: "offer", Data: json.RawMessage(offerBytes)}
		sendEnvelope(state, peerID, env)
		printSuccess("Offer sent to %s", shortID(peerID))

	case "listen":
		if state.ActiveClient == nil || state.ActiveClient.Id == "" {
			printWarning("Please 'init' or 'load' an identity first.")
			return true
		}
		msgs, err := state.Worker.Receive(state.Ctx, state.ActiveClient.IdentityPrivate)
		if err != nil {
			printError("Receive failed: %v", err)
			return true
		}
		if len(msgs) == 0 {
			printInfo("Inbox is empty.")
			return true
		}

		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]ChatMessage)
		}

		for _, m := range msgs {
			body := tryDecode(m.Body)
			var env PayloadEnvelope
			if err := json.Unmarshal(body, &env); err != nil {
				continue
			}

			switch env.Type {
			case "offer":
				var offer Client.HandshakeOffer
				_ = json.Unmarshal(env.Data, &offer)

				ansBytes, err := state.API.AcceptOffer(env.Data)
				if err != nil {
					printError("Failed to accept offer: %v", err)
					continue
				}

				ansEnv := PayloadEnvelope{Type: "answer", Data: json.RawMessage(ansBytes)}
				sendEnvelope(state, offer.SenderId, ansEnv)
				printSuccess("Auto-answered offer from %s", shortID(offer.SenderId))

			case "answer":
				peerID, err := state.API.FinishHandshake(env.Data)
				if err != nil {
					printError("Handshake finish failed: %v", err)
				} else {
					printSuccess("Session established with: %s", shortID(peerID))
				}

			case "message":
				senderID, pt, err := state.API.Decrypt(base64.StdEncoding.EncodeToString(env.Data))
				if err != nil {
					fmt.Printf("Error decrypting message: %v\n", err)
					continue
				}

				msgObj := ChatMessage{
					Body:   pt,
					IsRead: false,
				}

				state.Mailbox[senderID] = append([]ChatMessage{msgObj}, state.Mailbox[senderID]...)

				printMessage(fmt.Sprintf("New message received from %s! Check your mailbox.", senderID))

			}
		}

	case "mailbox":
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]ChatMessage)
		}

		// List all mailboxes if no peer is specified
		if len(args) == 0 {
			fmt.Printf("\n%s❖ Mailboxes ❖%s\n", Bold, Reset)
			if len(state.Mailbox) == 0 {
				printInfo("Your mailbox is empty.")
				return true
			}

			for peer, msgs := range state.Mailbox {
				hasUnread := false
				for _, msg := range msgs {
					if !msg.IsRead {
						hasUnread = true
						break
					}
				}

				indicator := ""
				if hasUnread {
					indicator = Yellow + " [*]" + Reset
				}
				fmt.Printf("  %s%s%s%s\n", Cyan, shortID(peer), Reset, indicator)
			}
			fmt.Println("\nType 'mailbox <peer_id>' to read.")
			return true
		}

		// Read specific mailbox
		targetPeer := args[0]
		fullPeerID := targetPeer

		for peer := range state.Mailbox {
			if strings.HasPrefix(peer, targetPeer) {
				fullPeerID = peer
				break
			}
		}

		msgs, exists := state.Mailbox[fullPeerID]
		if !exists {
			printWarning("No messages from %s", targetPeer)
			return true
		}

		fmt.Printf("\n%s❖ Messages with %s ❖%s\n", Bold, shortID(fullPeerID), Reset)
		for i, msg := range msgs {
			status := " "
			if !msg.IsRead {
				status = Yellow + "*" + Reset
				state.Mailbox[fullPeerID][i].IsRead = true // Mark as read
			}
			fmt.Printf(" [%s] %s\n", status, msg.Body)
		}
		fmt.Println()

	case "encrypt", "send":
		if len(args) < 2 {
			printWarning("Usage: send <peer> <msg>")
			return true
		}
		peer, msg := args[0], strings.Join(args[1:], " ")
		cipherBytes, err := state.API.Encrypt(peer, msg)
		if err != nil {
			printError("Encryption failed: %v", err)
			return true
		}
		sendEnvelope(state, peer, PayloadEnvelope{
			Type: "message", Data: cipherBytes,
		})

		// Optionally append sent message to mailbox as read
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]ChatMessage)
		}
		outMsg := ChatMessage{Body: "Me: " + msg, IsRead: true}
		state.Mailbox[peer] = append([]ChatMessage{outMsg}, state.Mailbox[peer]...)

		printSuccess("Message dispatched to %s", shortID(peer))

	case "help":
		t.Help()

	case "switch", "exit":
		return false

	default:
		printError("Unknown command. Type 'help'.")
	}
	return true
}

func (t *WorkerTransport) Help() {
	fmt.Printf("\n%sCommands:%s\n", Bold, Reset)
	fmt.Println("  init                  - Generate new identity & register")
	fmt.Println("  load <id>             - Load existing identity")
	fmt.Println("  connect <peer>        - Initiate handshake with peer")
	fmt.Println("  listen                - Poll inbox & process events")
	fmt.Println("  send <peer> <msg>     - Encrypt and dispatch message")
	fmt.Println("  mailbox               - List all active chats/mailboxes")
	fmt.Println("  mailbox <peer>        - Read messages from a specific peer")
	fmt.Println("  switch / exit         - Return to main menu")
}

// ---------------------------------------------------------
// 4. Main Runtime & TUI Loop
// ---------------------------------------------------------

func printMainMenu(entries []registry.Entry) {
	clearScreen()
	fmt.Printf("%s%s╔════════════════════════════════════════╗%s\n", bold, cyan, reset)
	fmt.Printf("%s%s║               NexTalk CLI              ║%s\n", bold, cyan, reset)
	fmt.Printf("%s%s╚════════════════════════════════════════╝%s\n\n", bold, cyan, reset)

	for i, e := range entries {
		if e.GUI != nil {
			fmt.Printf("  %d. %s\n", i+1, e.GUI.MenuLabel())
		}
	}
	fmt.Printf("  %d. Exit\n\n", len(entries)+1)
}

// ── TUI loop ──────────────────────────────────────────────────────────────────

// RunGUI is the top-level interactive shell. It reads all GUITransports from
// the registry — it never names a specific transport.
func RunGUI(api *core.Engine, cfg config.Config) {
	scanner := bufio.NewScanner(os.Stdin)
	state := registry.NewState(api, cfg)
	guiEntries := registry.GUITransports()
	exitChoice := fmt.Sprintf("%d", len(guiEntries)+1)

	for {
		printMainMenu(guiEntries)
		fmt.Printf("%sSelect ❯%s ", bold, reset)

		if !scanner.Scan() {
			break
		}
		choice := strings.TrimSpace(scanner.Text())

		if choice == exitChoice || choice == "exit" || choice == "q" {
			fmt.Printf("  %s[i]%s Goodbye!\n", cyan, reset)
			break
		}

		// Map 1-based choice to entry index.
		idx := -1
		for i := range guiEntries {
			if choice == fmt.Sprintf("%d", i+1) {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}

		t := guiEntries[idx].GUI
		if err := t.Init(state); err != nil {
			printError("Failed to initialise transport: %v", err)
			continue
		}

		// Sub-shell loop for the chosen transport.
		for {
			fmt.Printf("\n%s╭─[%snextalk:%s%s]\n╰─❯%s ",
				cyan, green, t.Name(), cyan, reset)

			if !scanner.Scan() {
				return
			}
			input := strings.TrimSpace(scanner.Text())
			if input == "" {
				continue
			}
			parts := strings.Fields(input)
			cmd, args := parts[0], parts[1:]

			if !t.Execute(state, cmd, args) {
				break // back to main menu
			}
		}
	}
}
