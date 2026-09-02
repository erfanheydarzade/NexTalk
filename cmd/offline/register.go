// cmd/offline/register.go
package offline

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/groupchat"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
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
		// Group-chat surface comes from the shared standard implementation.
		registry.PeersCommand(),
	}
	return append(append(specs, groupchat.Specs()...), registry.BaseCommands()...)
}

func (t *OfflineGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n  %s\n\n", ui.Header.Sprint("❖ Offline Mode — no network required ❖"))
	t.scanner = bufio.NewScanner(os.Stdin)
	state.InitFanout()
	return nil
}

func (t *OfflineGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
	// Group-chat surface (context / send-multi / contexts / mailbox) is the
	// shared standard implementation. Offline has no relay: send-multi
	// exports per-recipient transfer Containers instead of transmitting.
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
		ui.Successf("Identity: %s", state.ActiveClient.Id)

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
		state.InitFanout()

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
			ui.Errorf("%v", err)
			return true
		}

		bytes, err := state.ActiveClient.CreateOffer(peerID)
		if err != nil {
			ui.Errorf("Offer failed: %v", err)
			return true
		}
		state.RememberPeer(peerID)
		// Wire payloads are nanopack (binary) now — wrap in the base64
		// envelope so the paste-safe contract holds.
		env, err := wrapEnvelope("offer", bytes)
		if err != nil {
			ui.Errorf("Envelope failed: %v", err)
			return true
		}
		ui.Infof("OFFER ENVELOPE:\n%s", string(env))

	case "accept":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if t.scanner == nil {
			t.scanner = bufio.NewScanner(os.Stdin)
		}
		fmt.Print("  Paste offer envelope: ")
		t.scanner.Scan()
		offerRaw := strings.TrimSpace(t.scanner.Text())

		payload, err := parsePastedPayload(offerRaw)
		if err != nil {
			ui.Errorf("Accept failed: %v", err)
			return true
		}
		ansBytes, err := state.ActiveClient.AcceptOffer(payload)
		if err != nil {
			ui.Errorf("Accept failed: %v", err)
			return true
		}
		state.SyncPeersFromClient()
		env, err := wrapEnvelope("answer", ansBytes)
		if err != nil {
			ui.Errorf("Envelope failed: %v", err)
			return true
		}
		ui.Successf("ANSWER ENVELOPE:\n%s", string(env))

	case "finish":
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if t.scanner == nil {
			t.scanner = bufio.NewScanner(os.Stdin)
		}
		fmt.Print("  Paste answer envelope: ")
		t.scanner.Scan()
		ansRaw := strings.TrimSpace(t.scanner.Text())

		payload, err := parsePastedPayload(ansRaw)
		if err != nil {
			ui.Errorf("Finish failed: %v", err)
			return true
		}
		peerID, err := state.ActiveClient.FinishHandshake(payload)
		if err != nil {
			ui.Errorf("Finish failed: %v", err)
			return true
		}
		state.RememberPeer(peerID)
		ui.Successf("Session established: %s", peerID)

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
			ui.Errorf("%v", err)
			return true
		}
		message := strings.Join(args[1:], " ")

		var plaintext []byte

		if message != "" {
			plaintext = []byte(message)
		} else {
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
			ui.Errorf("Encrypt failed: %v", err)
			return true
		}
		state.RememberPeer(peer)
		ui.Successf("CIPHERTEXT JSON:\n%s", string(cipher))

	case "decrypt":
		if len(args) < 1 {
			fmt.Println("  Usage: decrypt <container-or-frame-or-b64>")
			return true
		}
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

		// Standard path first: transfer container or framed payload
		// (group deliveries AND plain messages both land in the mailbox).
		if ev, err := ingestStandard(state, args[0]); err == nil {
			switch ev.Kind {
			case "duplicate":
				ui.Infof("Already ingested — ignoring duplicate.")
			case "group_message":
				state.RememberPeer(ev.Sender)
				ui.Mailf("Group message in [%s] from %s — type 'mailbox %s'.",
					ev.Context, registry.ShortID(ev.Sender), ev.Context)
			default:
				state.RememberPeer(ev.Sender)
				ui.Successf("From %s: %s", ev.Sender, ev.Message)
			}
			return true
		} else if !errors.Is(err, groupchat.ErrNotFrame) {
			ui.Errorf("Decrypt failed: %v", err)
			return true
		}

		// Legacy path: bare base64 SecureMessage frame.
		ciphertext, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			ui.Errorf("Invalid ciphertext: %v", err)
			return true
		}
		senderID, plain, err := state.ActiveClient.Decrypt(ciphertext)
		if err != nil {
			ui.Errorf("Decrypt failed: %v", err)
			return true
		}
		if state.MailboxStore != nil {
			_ = state.MailboxStore.AppendIncoming(senderID, string(plain))
		}
		state.RememberPeer(senderID)
		ui.Successf("From %s: %s", senderID, plain)

	case "peers":
		state.PrintPeers("'offer <id>' or 'accept'")

	case "help":
		t.Help()

	case "switch", "exit":
		return false

	default:
		ui.Errorf("Unknown command. Type 'help'.")
	}
	return true
}

func (t *OfflineGUITransport) Help() {
	registry.RenderHelp(t.Commands())
}
