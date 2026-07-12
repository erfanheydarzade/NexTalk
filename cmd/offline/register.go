// cmd/offline/register.go
package offline

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
func (t *OfflineGUITransport) MenuLabel() string { return "1. Offline Mode  (Manual Cryptography Lab)" }

func (t *OfflineGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n  \033[1m\033[34m❖ Offline Mode — no network required ❖\033[0m\n\n")
	t.scanner = bufio.NewScanner(os.Stdin)
	return nil
}

func (t *OfflineGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
	switch cmd {
	case "init":
		state.ActiveClient = state.API.Initialize()
		fmt.Printf("\033[32m  [✓]\033[0m Identity: %s\n", state.ActiveClient.Id)

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

	case "offer":
		bytes, err := state.API.CreateOffer("")
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Offer failed: %v\n", err)
			return true
		}
		fmt.Printf("\033[36m  [i]\033[0m OFFER JSON:\n%s\n", string(bytes))

	case "accept":
		if t.scanner == nil {
			t.scanner = bufio.NewScanner(os.Stdin)
		}
		fmt.Print("  Paste offer JSON: ")
		t.scanner.Scan()
		offerRaw := strings.TrimSpace(t.scanner.Text())

		ansBytes, err := state.API.AcceptOffer([]byte(offerRaw))
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Accept failed: %v\n", err)
			return true
		}
		fmt.Printf("\033[32m  [✓]\033[0m ANSWER JSON:\n%s\n", string(ansBytes))

	case "finish":
		if t.scanner == nil {
			t.scanner = bufio.NewScanner(os.Stdin)
		}
		fmt.Print("  Paste answer JSON: ")
		t.scanner.Scan()
		ansRaw := strings.TrimSpace(t.scanner.Text())

		peerID, err := state.API.FinishHandshake([]byte(ansRaw))
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Finish failed: %v\n", err)
			return true
		}
		fmt.Printf("\033[32m  [✓]\033[0m Session established: %s\n", peerID)

	case "encrypt", "send":
		if len(args) < 2 {
			fmt.Println("  Usage: encrypt <peer> <msg>")
			return true
		}
		peer := args[0]
		msg := strings.Join(args[1:], " ")
		cipher, err := state.API.Encrypt(peer, msg)
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Encrypt failed: %v\n", err)
			return true
		}
		fmt.Printf("\033[32m  [✓]\033[0m CIPHERTEXT JSON:\n%s\n", string(cipher))

	case "decrypt":
		if len(args) < 1 {
			fmt.Println("  Usage: decrypt <ciphertext-json>")
			return true
		}
		senderID, plain, err := state.API.Decrypt(strings.Join(args, " "))
		if err != nil {
			fmt.Printf("\033[31m  [✗]\033[0m Decrypt failed: %v\n", err)
			return true
		}
		fmt.Printf("\033[32m  [✓]\033[0m From %s: %s\n", senderID, plain)

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
	fmt.Println("\n\033[1mCommands:\033[0m")
	fmt.Println("  init                  - Generate new identity")
	fmt.Println("  load <id>             - Load existing identity")
	fmt.Println("  offer                 - Generate a handshake offer (JSON)")
	fmt.Println("  accept                - Accept a peer's offer (paste JSON)")
	fmt.Println("  finish                - Finalise handshake (paste answer JSON)")
	fmt.Println("  encrypt <peer> <msg>  - Encrypt a message")
	fmt.Println("  decrypt <json>        - Decrypt a ciphertext")
	fmt.Println("  switch / exit         - Return to main menu")
}
