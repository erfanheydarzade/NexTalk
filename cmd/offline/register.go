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
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
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
		// Multi-message context commands
		{
			Name:  "context",
			Args:  []registry.ArgKind{registry.ArgText},
			Usage: "context <create|list|show|rename|add|exclude|include|members> ...",
			Help:  "Manage multi-message contexts",
		},
		{
			Name:     "send-multi",
			Args:     []registry.ArgKind{registry.ArgContext, registry.ArgText},
			Variadic: registry.ArgText,
			Usage:    "send-multi <context_id> <message>",
			Help:     "Send a multi-recipient message to context members",
		},
		{
			Name:  "contexts",
			Help:  "List all multi-message contexts",
		},
		registry.PeersCommand(),
	}
	return append(specs, registry.BaseCommands()...)
}

func (t *OfflineGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n  %s\n\n", ui.Header.Sprint("❖ Offline Mode — no network required ❖"))
	t.scanner = bufio.NewScanner(os.Stdin)
	state.InitFanout()
	return nil
}

func (t *OfflineGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
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
		ui.Infof("OFFER JSON:\n%s", string(bytes))

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
			ui.Errorf("Accept failed: %v", err)
			return true
		}
		state.SyncPeersFromClient()
		ui.Successf("ANSWER JSON:\n%s", string(ansBytes))

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
			fmt.Println("  Usage: decrypt <ciphertext-json>")
			return true
		}
		if state.ActiveClient == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}

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
		state.RememberPeer(senderID)
		ui.Successf("From %s: %s", senderID, plain)

	case "peers":
		state.PrintPeers("'offer <id>' or 'accept'")

	case "context":
		if state.Fanout == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if len(args) < 1 {
			fmt.Println("  Usage: context <create|list|show|rename|add|exclude|include|members> ...")
			return true
		}
		subCmd := args[0]
		switch subCmd {
		case "create":
			if len(args) < 2 {
				fmt.Println("  Usage: context create <name>")
				return true
			}
			name := strings.Join(args[1:], " ")
			ctx, err := state.Fanout.CreateContext(name, state.ActiveClient.IdentityPrivate)
			if err != nil {
				ui.Errorf("Context create failed: %v", err)
				return true
			}
			ui.Successf("Context created: %s (ID: %s)", ctx.DisplayName, ctx.ContextID)

		case "list", "ls":
			ctxs, err := state.Fanout.CtxStore.ListContexts()
			if err != nil {
				ui.Errorf("Context list failed: %v", err)
				return true
			}
			if len(ctxs) == 0 {
				ui.Infof("No contexts.")
				return true
			}
			fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Contexts ❖"))
			for _, c := range ctxs {
				fmt.Printf("  %s  v%d  %s\n", ui.Info.Sprint(c.ContextID), c.MetadataVersion, c.DisplayName)
			}

		case "show":
			if len(args) < 2 {
				fmt.Println("  Usage: context show <context_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			ctx, err := state.Fanout.CtxStore.LoadContext(ctxID)
			if err != nil {
				ui.Errorf("Context not found: %v", err)
				return true
			}
			policies, _ := state.Fanout.ListRecipientPolicies(ctxID)
			fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Context: %s ❖", ctx.DisplayName))
			fmt.Printf("  ID:      %s\n", ctx.ContextID)
			fmt.Printf("  Version: %d\n", ctx.MetadataVersion)
			fmt.Printf("  Creator: %s\n", ctx.CreatorID)
			fmt.Printf("\n  Members:\n")
			if len(policies) == 0 {
				fmt.Println("    (none configured)")
			}
			for _, p := range policies {
				icon := "✓"
				switch p.Policy {
				case multimsg.PolicyEnabled:
					icon = "✓"
				case multimsg.PolicyMuted:
					icon = "~"
				case multimsg.PolicyBlocked:
					icon = "✗"
				case multimsg.PolicyExcluded:
					icon = "⊘"
				}
				fmt.Printf("    %s %s  (%s)\n", icon, registry.ShortID(p.Recipient), p.Policy.String())
			}

		case "rename":
			if len(args) < 3 {
				fmt.Println("  Usage: context rename <context_id> <new_name>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			newName := strings.Join(args[2:], " ")
			ctx, err := state.Fanout.UpdateContext(ctxID, newName, state.ActiveClient.IdentityPrivate)
			if err != nil {
				ui.Errorf("Context rename failed: %v", err)
				return true
			}
			ui.Successf("Context renamed: %s (v%d)", ctx.DisplayName, ctx.MetadataVersion)

		case "add":
			if len(args) < 3 {
				fmt.Println("  Usage: context add <context_id> <peer_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			peerID, err := state.ResolvePeer(args[2])
			if err != nil {
				ui.Errorf("Peer resolution failed: %v", err)
				return true
			}
			if err := state.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyEnabled); err != nil {
				ui.Errorf("Add failed: %v", err)
				return true
			}
			ui.Successf("Added %s to context %s", registry.ShortID(peerID), ctxID)

		case "exclude", "remove":
			if len(args) < 3 {
				fmt.Println("  Usage: context exclude <context_id> <peer_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			peerID, err := state.ResolvePeer(args[2])
			if err != nil {
				ui.Errorf("Peer resolution failed: %v", err)
				return true
			}
			if err := state.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyExcluded); err != nil {
				ui.Errorf("Exclude failed: %v", err)
				return true
			}
			ui.Successf("Excluded %s from context %s (local delivery exclusion)", registry.ShortID(peerID), ctxID)

		case "include":
			if len(args) < 3 {
				fmt.Println("  Usage: context include <context_id> <peer_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			peerID, err := state.ResolvePeer(args[2])
			if err != nil {
				ui.Errorf("Peer resolution failed: %v", err)
				return true
			}
			if err := state.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyEnabled); err != nil {
				ui.Errorf("Include failed: %v", err)
				return true
			}
			ui.Successf("Re-enabled %s in context %s", registry.ShortID(peerID), ctxID)

		case "block":
			if len(args) < 3 {
				fmt.Println("  Usage: context block <context_id> <peer_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			peerID, err := state.ResolvePeer(args[2])
			if err != nil {
				ui.Errorf("Peer resolution failed: %v", err)
				return true
			}
			if err := state.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyBlocked); err != nil {
				ui.Errorf("Block failed: %v", err)
				return true
			}
			ui.Successf("Blocked %s in context %s", registry.ShortID(peerID), ctxID)

		case "mute":
			if len(args) < 3 {
				fmt.Println("  Usage: context mute <context_id> <peer_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			peerID, err := state.ResolvePeer(args[2])
			if err != nil {
				ui.Errorf("Peer resolution failed: %v", err)
				return true
			}
			if err := state.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyMuted); err != nil {
				ui.Errorf("Mute failed: %v", err)
				return true
			}
			ui.Successf("Muted %s in context %s", registry.ShortID(peerID), ctxID)

		case "members":
			if len(args) < 2 {
				fmt.Println("  Usage: context members <context_id>")
				return true
			}
			ctxID := multimsg.ContextID(args[1])
			ctx, err := state.Fanout.CtxStore.LoadContext(ctxID)
			if err != nil {
				ui.Errorf("Context not found: %v", err)
				return true
			}
			policies, _ := state.Fanout.ListRecipientPolicies(ctxID)
			fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Members of %s ❖", ctx.DisplayName))
			if len(policies) == 0 {
				fmt.Println("    (none configured)")
			}
			for _, p := range policies {
				icon := "✓"
				switch p.Policy {
				case multimsg.PolicyEnabled:
					icon = "✓"
				case multimsg.PolicyMuted:
					icon = "~"
				case multimsg.PolicyBlocked:
					icon = "✗"
				case multimsg.PolicyExcluded:
					icon = "⊘"
				}
				fmt.Printf("    %s %s  [%s]\n", icon, registry.ShortID(p.Recipient), p.Policy.String())
			}

		default:
			ui.Errorf("Unknown context subcommand: %s", subCmd)
		}

	case "send-multi":
		if state.Fanout == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		if len(args) < 2 {
			fmt.Println("  Usage: send-multi <context_id> <message>")
			return true
		}
		ctxID := multimsg.ContextID(args[0])
		message := strings.Join(args[1:], " ")

		// Get effective recipients from context policies
		policies, err := state.Fanout.ListRecipientPolicies(ctxID)
		if err != nil {
			ui.Errorf("Context not found: %v", err)
			return true
		}
		var recipients []string
		for _, p := range policies {
			if p.Policy != multimsg.PolicyBlocked && p.Policy != multimsg.PolicyExcluded {
				recipients = append(recipients, p.Recipient)
			}
		}
		if len(recipients) == 0 {
			ui.Warnf("No enabled recipients in context %s", ctxID)
			return true
		}

		result, err := state.Fanout.SendMultiMessage(state.Ctx, ctxID, []byte(message), recipients)
		if err != nil {
			ui.Errorf("Multi-send failed: %v", err)
			return true
		}

		fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Multi-message: %s ❖", result.MessageID))
		fmt.Printf("  Context: %s\n", ctxID)
		fmt.Printf("\n  Deliveries:\n")
		for _, d := range result.Deliveries {
			icon := " "
			status := ""
			switch d.Status {
			case multimsg.DeliverySent:
				icon = ui.Success.Sprint("✓")
				status = "sent"
			case multimsg.DeliveryPending:
				icon = ui.Warning.Sprint("~")
				status = "pending (no session)"
			case multimsg.DeliveryFailed:
				icon = ui.Fail.Sprint("✗")
				status = "failed"
				if d.Error != nil {
					status += ": " + d.Error.Error()
				}
			}
			fmt.Printf("    %s %s  %s\n", icon, registry.ShortID(d.Recipient), status)
		}
		fmt.Printf("\n  Summary: %d sent, %d pending, %d failed\n",
			result.SuccessCount(), result.PendingCount(), result.FailedCount())

	case "contexts":
		if state.Fanout == nil {
			fmt.Println("  Please 'init' or 'load' an identity first.")
			return true
		}
		ctxs, err := state.Fanout.CtxStore.ListContexts()
		if err != nil {
			ui.Errorf("Context list failed: %v", err)
			return true
		}
		if len(ctxs) == 0 {
			ui.Infof("No contexts.")
			return true
		}
		fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Contexts ❖"))
		for _, c := range ctxs {
			fmt.Printf("  %s  v%d  %s\n", ui.Info.Sprint(c.ContextID), c.MetadataVersion, c.DisplayName)
		}

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
