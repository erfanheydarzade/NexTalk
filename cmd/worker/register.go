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
		{
			Name:  "mailbox",
			Args:  []registry.ArgKind{registry.ArgPeer},
			Usage: "mailbox [peer]",
			Help:  "List chats, or read one peer's messages",
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

func (t *WorkerGUITransport) Init(state *registry.State) error {
	fmt.Printf("\n%s\n\n", ui.Header.Sprint("❖ Worker Mode Engaged (Cloud Relay) ❖"))

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
	state.InitFanout()
	return nil
}

func (t *WorkerGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
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

		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}
		state.Mailbox[peer] = append(
			[]registry.ChatMessage{{Body: "Me: " + message, IsRead: true}},
			state.Mailbox[peer]...,
		)
		state.RememberPeer(peer)
		ui.Successf("Message sent to %s", registry.ShortID(peer))

	case "peers":
		state.PrintPeers("'connect <id>' or 'listen'")

	case "mailbox":
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}

		if len(args) == 0 {
			// Show both regular mailboxes and contexts
			hasMailbox := len(state.Mailbox) > 0
			hasContexts := len(state.Contexts) > 0

			if !hasMailbox && !hasContexts {
				ui.Infof("Mailbox is empty.")
				return true
			}

			if hasMailbox {
				fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Mailboxes ❖"))
				for peer, msgs := range state.Mailbox {
					unread := 0
					for _, m := range msgs {
						if !m.IsRead {
							unread++
						}
					}
					indicator := ""
					if unread > 0 {
						indicator = ui.Warning.Sprintf(" [%d unread]", unread)
					}
					fmt.Printf("  %s%s\n", ui.Info.Sprint(registry.ShortID(peer)), indicator)
				}
			}

			if hasContexts {
				fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Contexts ❖"))
				for key, msgs := range state.Contexts {
					unread := 0
					for _, m := range msgs {
						if !m.IsRead {
							unread++
						}
					}
					indicator := ""
					if unread > 0 {
						indicator = ui.Warning.Sprintf(" [%d unread]", unread)
					}
					// Strip "ctx:" prefix for display
					displayKey := key
					if len(key) > 4 && key[:4] == "ctx:" {
						displayKey = key[4:]
					}
					fmt.Printf("  %s%s\n", ui.Info.Sprint(displayKey), indicator)
				}
			}

			fmt.Println("\nType 'mailbox <peer_id>' or 'contexts <key>' to read (Tab completes).")
			return true
		}

		fullPeer, err := state.ResolvePeer(args[0])
		if err != nil {
			ui.Errorf("%v", err)
			return true
		}

		msgs, ok := state.Mailbox[fullPeer]
		if !ok {
			ui.Warnf("No messages from %s", registry.ShortID(fullPeer))
			return true
		}

		fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Messages with %s ❖", registry.ShortID(fullPeer)))
		for i, m := range msgs {
			mark := " "
			if !m.IsRead {
				mark = ui.Warning.Sprint("*")
				state.Mailbox[fullPeer][i].IsRead = true
			}
			fmt.Printf("  [%s] %s\n", mark, m.Body)
		}
		fmt.Println()

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

func (t *WorkerGUITransport) Help() {
	registry.RenderHelp(t.Commands())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func dispatchGUI(state *registry.State, t relay.Type, data []byte) {
	switch t {

	case relay.TypeOffer:
		var offer core.HandShakeOffer
		if err := json.Unmarshal(data, &offer); err != nil {
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
			ui.Errorf("Decrypt failed: %v", err)
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
		ui.Mailf("New message from %s — check 'mailbox'.", registry.ShortID(senderID))

	case relay.TypeMultiMsg:
		// Process multi-message delivery
		if state.Fanout == nil {
			ui.Warnf("Multi-message received but fanout not initialized")
			return
		}
		// For now, treat multi-message like a regular message
		// The fanout layer handles deduplication and grouping
		senderID, pt, err := state.ActiveClient.Decrypt(data)
		if err != nil {
			ui.Errorf("Multi-message decrypt failed: %v", err)
			return
		}
		if state.Mailbox == nil {
			state.Mailbox = make(map[string][]registry.ChatMessage)
		}
		// Store in context-specific mailbox if we can identify the context
		// For now, store in sender's mailbox with a prefix
		contextKey := "ctx:" + senderID
		state.Contexts[contextKey] = append(
			[]registry.ChatMessage{{Body: "[multi] " + string(pt), IsRead: false}},
			state.Contexts[contextKey]...,
		)
		state.RememberPeer(senderID)
		ui.Mailf("Multi-message from %s — check contexts.", registry.ShortID(senderID))

	default:
		ui.Warnf("Unknown envelope type: %d", t)
	}
}
