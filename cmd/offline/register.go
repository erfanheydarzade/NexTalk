// cmd/offline/register.go
package offline

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	registry.Register(registry.Entry{
		GUI:       &OfflineGUITransport{},
		CLI:       &offlineCLITransport{},
		MenuOrder: 1,
	})
}

// ── CLI face ──────────────────────────────────────────────────────────────────

type offlineCLITransport struct{}

func (o *offlineCLITransport) RegisterCLI(parent *cobra.Command, engine *core.Engine, _ config.Config) {
	Register(parent, engine) // existing package-level Register
}

// ── GUI face ──────────────────────────────────────────────────────────────────

type OfflineGUITransport struct {
	scanner *bufio.Scanner
}

func (t *OfflineGUITransport) Name() string      { return "offline" }
func (t *OfflineGUITransport) MenuLabel() string { return "Offline Mode  (Manual Cryptography Lab)" }

// Commands implements registry.CompletionProvider — the single source of truth
// for Tab completion and Help() in offline mode.
//
// Note this list deliberately differs from the worker transport's: offline has
// offer/accept/finish/decrypt and no listen. The old shared, hard-coded
// completion list offered `listen` here (which does nothing) and omitted every
// command in this list, which is the "wrong commands complete" half of the bug.
func (t *OfflineGUITransport) Commands() []registry.CommandSpec {
	specs := []registry.CommandSpec{
		{
			Name: "init",
			Help: "Generate a new identity",
		},
		registry.IdentityCommand("Load an existing local identity (Tab lists ./<id>.json files)"),
		{
			Name:  "offer",
			Args:  []registry.ArgKind{registry.ArgPeer},
			Usage: "offer <peer>",
			Help:  "Generate a handshake offer for a peer (JSON)",
		},
		{
			Name: "accept",
			Help: "Accept a peer's offer (prompts for the offer JSON)",
		},
		{
			Name: "finish",
			Help: "Finalise a handshake (prompts for the answer JSON)",
		},
		func() registry.CommandSpec {
			s := registry.MessageCommand("encrypt", "send")
			s.Help = "Encrypt a message for an established peer"
			return s
		}(),
		{
			Name:     "decrypt",
			Args:     []registry.ArgKind{registry.ArgText},
			Variadic: registry.ArgText,
			Usage:    "decrypt <b64>",
			Help:     "Decrypt a base64 ciphertext frame",
		},
		registry.PeersCommand(),
	}
	return append(specs, registry.BaseCommands()...)
}

func (t *OfflineGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n  \033[1m\033[34m❖ Offline Mode — no network required ❖\033[0m\n\n")
	t.scanner = bufio.NewScanner(os.Stdin)
	return nil
}

func (t *OfflineGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
	switch cmd {
	case "init":
		state.ActiveClient = Client.NewClient()
		fmt.Printf("\033[32m  [✓]\033[0m Identity: %s\n", state.ActiveClient.Id)

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

		// Peers persisted in <id>.json become Tab-completable immediately,
		// so a restarted shell doesn't lose them.
		state.SyncPeersFromClient()

	case "offer":
		if len(args) < 1 {
			fmt.Println("  Usage: offer <peer>")
			return true
		}
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

		peerID, err := state.ResolvePeer(args[0])
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m %v\n", err)
			return true
		}

		bytes, err := state.ActiveClient.CreateOffer(peerID)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Offer failed: %v\n", err)
			return true
		}
		// Remember the target now so the follow-up 'encrypt' can Tab-complete
		// it instead of requiring the full ID to be retyped.
		state.RememberPeer(peerID)
		fmt.Printf("\033[36m  [i]\033[0m OFFER JSON:\n%s\n", string(bytes))

	case "accept":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if t.scanner == nil {
			t.scanner = bufio.NewScanner(os.Stdin)
		}
		fmt.Print("  Paste offer JSON: ")
		t.scanner.Scan()
		offerRaw := strings.TrimSpace(t.scanner.Text())

		ansBytes, err := state.ActiveClient.AcceptOffer([]byte(offerRaw))
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Accept failed: %v\n", err)
			return true
		}
		// AcceptOffer stores the new session under the sender's ID, so
		// syncing from the client is enough to make that peer completable —
		// no need to re-parse the offer JSON just to learn who sent it.
		state.SyncPeersFromClient()
		fmt.Printf("\033[32m  [✓]\033[0m ANSWER JSON:\n%s\n", string(ansBytes))

	case "finish":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if t.scanner == nil {
			t.scanner = bufio.NewScanner(os.Stdin)
		}
		fmt.Print("  Paste answer JSON: ")
		t.scanner.Scan()
		ansRaw := strings.TrimSpace(t.scanner.Text())

		peerID, err := state.ActiveClient.FinishHandshake([]byte(ansRaw))
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Finish failed: %v\n", err)
			return true
		}
		state.RememberPeer(peerID)
		fmt.Printf("\033[32m  [✓]\033[0m Session established: %s\n", peerID)

	case "encrypt", "send":
		if len(args) < 2 {
			fmt.Println("  Usage: encrypt <peer> <msg>")
			return true
		}
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

		peer, err := state.ResolvePeer(args[0])
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m %v\n", err)
			return true
		}
		message := strings.Join(args[1:], " ")

		var plaintext []byte

		if message != "" {
			// Text codec from CLI
			plaintext = []byte(message)
		} else {
			// Binary/text codec from stdin
			plaintext, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Println("failed to read stdin: %w", err)
			}

			if len(plaintext) == 0 {
				fmt.Println("no codec provided")
			}
		}

		cipher, err := state.ActiveClient.Encrypt(peer, plaintext)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Encrypt failed: %v\n", err)
			return true
		}
		state.RememberPeer(peer)
		fmt.Printf("\033[32m  [✓]\033[0m CIPHERTEXT JSON:\n%s\n", string(cipher))

	case "decrypt":
		if len(args) < 1 {
			fmt.Println("  Usage: decrypt <ciphertext-json>")
			return true
		}
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

		ciphertext, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Invalid ciphertext: %v\n", err)
			return true
		}
		senderID, plain, err := state.ActiveClient.Decrypt(ciphertext)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Decrypt failed: %v\n", err)
			return true
		}
		state.RememberPeer(senderID)
		fmt.Printf("\033[32m  [✓]\033[0m From %s: %s\n", senderID, plain)

	case "peers":
		state.PrintPeers("'offer <id>' or 'accept'")

	case "help":
		t.Help()

	case "switch", "exit":
		return false

	default:
		fmt.Printf("\033[31m  [✗]\033[0m Unknown command. Type 'help'.\n")
	}
	return true
}

func (t *OfflineGUITransport) Help() {
	// Rendered from the same specs that drive Tab completion, so help and
	// completion can never disagree about what exists.
	registry.RenderHelp(t.Commands())
}
