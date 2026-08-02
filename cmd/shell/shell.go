package shell

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/chzyer/readline"
	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
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

// shortID visually trims long keys (e.g., 911ef9...4f28) for display only.
// Full IDs are always used internally — this never affects matching/lookup.
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

// ChatMessage is an alias for registry.ChatMessage — registry.State.Mailbox
// is declared as map[string][]registry.ChatMessage, so this file must use
// the exact same type rather than a locally-declared lookalike struct.
type ChatMessage = registry.ChatMessage

// RuntimeState is an alias for registry.State, NOT a separate struct.
// registry.GUITransport.Execute/Init are defined against *registry.State —
// if RuntimeState were its own distinct struct type (even with identical
// fields), it would NOT satisfy that interface, since Go interface
// satisfaction requires the actual declared type to match, not just its
// shape. Aliasing keeps every function in this file working against the
// exact type the registry package (and thus every GUITransport, including
// WorkerTransport) is compiled against.
//
// This assumes registry.State exposes: API, ActiveClient, Config, Worker,
// Ctx, Mailbox with the same field names/types used below. If registry.State
// does not yet have a Mailbox field (map[string][]ChatMessage) or a Worker
// field (relay.Relay), add them there — this file only aliases the type, it
// doesn't declare those fields itself.
type RuntimeState = registry.State

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

// resolvePeerID takes what the user typed and resolves it against known
// mailbox peers. Exact match always wins first (so a full ID never gets
// accidentally reinterpreted). Only if there's no exact match does it try
// unique-prefix matching — and it REFUSES to guess if the prefix is
// ambiguous (matches more than one peer), returning an error instead of
// silently picking one. This is a safety property: never send a message to
// the wrong peer because of a truncated/ambiguous ID.
func resolvePeerID(state *RuntimeState, input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty peer id")
	}
	if _, ok := state.Mailbox[input]; ok {
		return input, nil
	}

	var matches []string
	for peer := range state.Mailbox {
		if strings.HasPrefix(peer, input) {
			matches = append(matches, peer)
		}
	}

	switch len(matches) {
	case 0:
		// Not a known peer at all — treat input as a literal full ID.
		// (Lets users message someone they've never chatted with yet,
		// e.g. right after a fresh 'connect'.)
		return input, nil
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf(
			"ambiguous peer prefix %q matches %d known peers: %s",
			input, len(matches), strings.Join(shortIDs(matches), ", "),
		)
	}
}

func shortIDs(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = shortID(id)
	}
	return out
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

// confirmPrompt asks a plain y/N question on stdin. Used to gate anything
// that changes trust state (accepting a handshake) — nothing auto-accepts
// silently anymore.
func confirmPrompt(reader *bufio.Reader, format string, args ...any) bool {
	fmt.Printf(Yellow+"  [?] "+Reset+format, args...)
	line, _ := reader.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
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
		state.ActiveClient = Client.NewClient()
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
		cl, err := Client.LoadClient(args[0])
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
		peerID, err := resolvePeerID(state, args[0])
		if err != nil {
			printError("%v", err)
			return true
		}
		offerBytes, err := state.ActiveClient.CreateOffer(peerID)
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

		// One reader reused across every message in this batch — creating a
		// fresh bufio.Reader per iteration would drop any buffered input.
		stdinReader := bufio.NewReader(os.Stdin)

		for _, m := range msgs {
			body := tryDecode(m.Body)
			var env PayloadEnvelope
			if err := json.Unmarshal(body, &env); err != nil {
				continue
			}

			switch env.Type {
			case "offer":
				var offer core.HandShakeOffer
				if err := json.Unmarshal(env.Data, &offer); err != nil {
					printError("Malformed offer received, ignoring.")
					continue
				}

				accepted := confirmPrompt(
					stdinReader,
					"Incoming handshake request from %s%s%s — accept? [y/N]: ",
					Bold, offer.SenderId, Reset,
				)
				if !accepted {
					printWarning("Ignored handshake offer from %s", shortID(offer.SenderId))
					continue
				}

				ansBytes, err := state.ActiveClient.AcceptOffer(env.Data)
				if err != nil {
					printError("Failed to accept offer: %v", err)
					continue
				}

				ansEnv := PayloadEnvelope{Type: "answer", Data: json.RawMessage(ansBytes)}
				sendEnvelope(state, offer.SenderId, ansEnv)
				printSuccess("Answered offer from %s", shortID(offer.SenderId))

			case "answer":
				peerID, err := state.ActiveClient.FinishHandshake(env.Data)
				if err != nil {
					printError("Handshake finish failed: %v", err)
				} else {

					if _, ok := state.Mailbox[peerID]; !ok {
						state.Mailbox[peerID] = []ChatMessage{}
					}

					printSuccess("Session established with: %s", shortID(peerID))
				}

			case "message":
				senderID, pt, err := state.ActiveClient.Decrypt(env.Data)
				if err != nil {
					printError("Error decrypting message: %v", err)
					continue
				}

				// Full message body is kept as-is — no truncation, no size cap.
				msgObj := ChatMessage{
					Body:   string(pt),
					IsRead: false,
				}

				state.Mailbox[senderID] = append([]ChatMessage{msgObj}, state.Mailbox[senderID]...)

				printMessage("New message received from %s! Check 'mailbox'.", shortID(senderID))
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

			peers := make([]string, 0, len(state.Mailbox))
			for peer := range state.Mailbox {
				peers = append(peers, peer)
			}
			sort.Strings(peers)

			for _, peer := range peers {
				unread := 0
				for _, msg := range state.Mailbox[peer] {
					if !msg.IsRead {
						unread++
					}
				}
				indicator := ""
				if unread > 0 {
					indicator = fmt.Sprintf(Yellow+" [%d unread]"+Reset, unread)
				}
				fmt.Printf("  %s%s%s%s\n", Cyan, shortID(peer), Reset, indicator)
			}
			fmt.Println("\nType 'mailbox <peer_id>' to read (partial ID ok if unambiguous).")
			return true
		}

		// Read specific mailbox — resolves partial/prefix IDs safely.
		fullPeerID, err := resolvePeerID(state, args[0])
		if err != nil {
			printError("%v", err)
			return true
		}

		msgs, exists := state.Mailbox[fullPeerID]
		if !exists {
			printWarning("No messages from %s", args[0])
			return true
		}

		fmt.Printf("\n%s❖ Messages with %s ❖%s\n", Bold, shortID(fullPeerID), Reset)
		for i, msg := range msgs {
			status := " "
			if !msg.IsRead {
				status = Yellow + "*" + Reset
				state.Mailbox[fullPeerID][i].IsRead = true // Mark as read
			}
			// Full body printed, unmodified — no length limit.
			fmt.Printf(" [%s] %s\n", status, msg.Body)
		}
		fmt.Println()

	case "encrypt", "send":
		if len(args) < 2 {
			printWarning("Usage: send <peer> <msg>")
			return true
		}
		peer, err := resolvePeerID(state, args[0])
		if err != nil {
			printError("%v", err)
			return true
		}
		message := strings.Join(args[1:], " ")

		var plaintext []byte

		if message != "" {
			plaintext = []byte(message)
		} else {
			plaintext, err = io.ReadAll(os.Stdin)
			if err != nil {
				printError("Failed to read stdin: %v", err)
				return true
			}
			if len(plaintext) == 0 {
				printWarning("No content provided.")
				return true
			}
		}

		cipherBytes, err := state.ActiveClient.Encrypt(peer, plaintext)
		if err != nil {
			printError("Encryption failed: %v", err)
			return true
		}
		sendEnvelope(state, peer, PayloadEnvelope{
			Type: "message", Data: cipherBytes,
		})

		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]ChatMessage)
		}
		outMsg := ChatMessage{Body: "Me: " + message, IsRead: true}
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
	fmt.Println("  connect <peer>        - Initiate handshake with peer (partial id ok)")
	fmt.Println("  listen                - Poll inbox & process events (asks before accepting handshakes)")
	fmt.Println("  send <peer> <msg>     - Encrypt and dispatch message (partial id ok)")
	fmt.Println("  mailbox               - List all active chats/mailboxes")
	fmt.Println("  mailbox <peer>        - Read messages from a specific peer (partial id ok)")
	fmt.Println("  switch / exit         - Return to main menu")
	fmt.Println("\nTip: press Tab to autocomplete commands and known peer IDs.")
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

// shellCompleter implements readline.AutoCompleter. It completes the
// command name in the first word position, and known peer IDs (from the
// live mailbox map) for any command that takes a peer as its first argument.
// It re-reads state.Mailbox on every keystroke, so newly-seen peers (from a
// 'listen' run moments ago) are completable immediately without restarting
// the sub-shell.
type shellCompleter struct {
	state *RuntimeState
}

var peerArgCommands = map[string]bool{
	"connect": true,
	"send":    true,
	"encrypt": true,
	"mailbox": true,
}

var allCommands = []string{
	"init", "load", "connect", "listen", "send", "mailbox", "help", "switch", "exit",
}

func (c *shellCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	input := string(line[:pos])
	fields := strings.Fields(input)

	lastSpace := strings.LastIndexByte(input, ' ')
	prefix := ""
	if lastSpace >= 0 {
		prefix = input[lastSpace+1:]
	} else {
		prefix = input
	}

	// Completing the first word: command name.
	if lastSpace == -1 {
		for _, cmdName := range allCommands {
			if strings.HasPrefix(cmdName, prefix) {
				newLine = append(newLine, []rune(cmdName[len(prefix):]))
			}
		}
		return newLine, len(prefix)
	}

	if len(fields) == 0 || !peerArgCommands[fields[0]] {
		return nil, 0
	}

	// How many "words" are already fully typed (i.e. not counting the one
	// currently being completed)? If the cursor is right after a space,
	// input ends in " " so fields doesn't include an in-progress word.
	typedWords := len(fields)
	if !strings.HasSuffix(input, " ") {
		// the last field IS the in-progress prefix; don't double count it
		typedWords--
	}

	// send/encrypt take <peer> <msg...> — only the peer slot (word 1) should
	// complete peer IDs; the message body afterwards is free text.
	// connect/mailbox take <peer> as their only/last meaningful arg, so any
	// argument position should offer peer completion (covers re-editing,
	// retyping, or completing after a typo'd earlier word).
	offerPeers := false
	switch fields[0] {
	case "send", "encrypt":
		offerPeers = typedWords == 1
	case "connect", "mailbox":
		offerPeers = typedWords >= 1
	}
	if !offerPeers {
		return nil, 0
	}

	peers := make([]string, 0, len(c.state.Mailbox))
	for peer := range c.state.Mailbox {
		if strings.HasPrefix(peer, prefix) {
			peers = append(peers, peer)
		}
	}
	sort.Strings(peers)
	for _, peer := range peers {
		newLine = append(newLine, []rune(peer[len(prefix):]))
	}
	return newLine, len(prefix)
}

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

		runSubShell(state, t)
	}
}

// runSubShell drives the readline-backed loop for a single chosen transport.
// It builds a fresh readline.Instance per transport so the prompt reflects
// the transport's name, and the completer always sees the current state.
func runSubShell(state *RuntimeState, t registry.GUITransport) {
	fmt.Printf("\n%s╭─[%snextalk:%s%s]\n",
		cyan,
		green,
		t.Name(),
		cyan,
	)

	prompt := fmt.Sprintf("%s╰─❯ %s", green, reset)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          prompt,
		AutoComplete:    &shellCompleter{state: state},
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		printError("Failed to start input shell: %v", err)
		return
	}
	defer rl.Close()

	for {
		input, err := rl.Readline()
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			return
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		parts := strings.Fields(input)
		cmd, args := parts[0], parts[1:]

		if !t.Execute(state, cmd, args) {
			return // back to main menu
		}
	}
}
