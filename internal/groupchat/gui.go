// Package groupchat is THE shared multi-message (group chat) implementation
// for every NexTalk transport — worker, offline, proxy, wasm.
//
// One definition of the user-facing surface lives here:
//
//   - Specs()   — the interactive-shell command specs (with slot-aware Tab
//     completion) for `context`, `send-multi`, `contexts`, and `mailbox`.
//   - Execute() — the behavior behind those commands, against registry.State
//     (Fanout + MailboxStore), identical no matter which transport calls it.
//   - CLI builders (cli.go) — the same surface as cobra subcommands.
//
// Transports differ only in what they can contribute:
//
//   - state.Worker != nil (worker): deliveries are transmitted through the
//     relay automatically.
//   - state.Worker == nil (offline / local-only proxy): send-multi still
//     encrypts one copy per recipient and emits each as a transfer Container
//     (internal/frame) for manual delivery; ingest happens wherever frames
//     enter the transport (e.g. offline decrypt).
package groupchat

import (
	"fmt"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// ── Command surface ──────────────────────────────────────────────────────────

// contextSubcommands is the full `context <word>` vocabulary, in completion
// order.
var contextSubcommands = []string{
	"create", "list", "show", "rename",
	"add", "exclude", "remove", "include",
	"mute", "block", "members",
}

// contextPeerSubcommands take a <ctx> then a <peer> argument.
var contextPeerSubcommands = map[string]bool{
	"add": true, "exclude": true, "remove": true,
	"include": true, "mute": true, "block": true,
}

// ContextCommandSpec returns the slot-aware `context` spec.
func ContextCommandSpec() registry.CommandSpec {
	return registry.CommandSpec{
		Name: "context",
		Complete: func(s *registry.State, typed []string, argIndex int, fragment string) []string {
			return CompleteContextArgs(s, typed, argIndex, fragment)
		},
		Usage: "context <create|list|show|rename|add|exclude|remove|include|mute|block|members> ...",
		Help:  "Manage multi-message contexts (groups)",
	}
}

// Specs returns every group-chat command spec, ready to append to a
// transport's Commands().
func Specs() []registry.CommandSpec {
	return []registry.CommandSpec{
		ContextCommandSpec(),
		{
			Name:     "send-multi",
			Args:     []registry.ArgKind{registry.ArgContext, registry.ArgText},
			Variadic: registry.ArgText,
			Usage:    "send-multi <context_id> <message>",
			Help:     "Encrypt one copy per member; relay or export containers",
		},
		{
			Name: "contexts",
			Help: "List all multi-message contexts",
		},
		{
			Name:  "mailbox",
			Args:  []registry.ArgKind{registry.ArgThread},
			Usage: "mailbox [peer|group]",
			Help:  "List chats & groups, or read one thread (marks read)",
		},
	}
}

// Handles reports whether this package owns the given shell command word.
func Handles(cmd string) bool {
	switch cmd {
	case "context", "send-multi", "contexts", "mailbox":
		return true
	}
	return false
}

// Execute runs one group-chat shell command. It returns false only when the
// command word is not ours — callers check Handles first or treat false as
// "not mine, keep going".
func Execute(state *registry.State, cmd string, args []string) bool {
	switch cmd {

	case "context":
		execContext(state, args)

	case "send-multi":
		execSendMulti(state, args)

	case "contexts":
		execContextsList(state)

	case "mailbox":
		execMailbox(state, args)

	default:
		return false
	}
	return true
}

// ── context ──────────────────────────────────────────────────────────────────

func execContext(state *registry.State, args []string) {
	if state.Fanout == nil {
		fmt.Println("  Please 'init' or 'load' an identity first.")
		return
	}
	if len(args) < 1 {
		fmt.Println("  Usage: context <create|list|show|rename|add|exclude|remove|include|mute|block|members> ...")
		return
	}
	sub := args[0]
	switch sub {
	case "create":
		if len(args) < 2 {
			fmt.Println("  Usage: context create <name>")
			return
		}
		name := strings.Join(args[1:], " ")
		ctx, err := state.Fanout.CreateContext(name, state.ActiveClient.IdentityPrivate)
		if err != nil {
			ui.Errorf("Context create failed: %v", err)
			return
		}
		ui.Successf("Context created: %s (ID: %s)", ctx.DisplayName, ctx.ContextID)

	case "list", "ls":
		listContexts(state.Fanout.CtxStore)

	case "show":
		if len(args) < 2 {
			fmt.Println("  Usage: context show <context_id>")
			return
		}
		showContext(state.Fanout.CtxStore, multimsg.ContextID(args[1]))

	case "rename":
		if len(args) < 3 {
			fmt.Println("  Usage: context rename <context_id> <new_name>")
			return
		}
		ctxID := multimsg.ContextID(args[1])
		newName := strings.Join(args[2:], " ")
		ctx, err := state.Fanout.UpdateContext(ctxID, newName, state.ActiveClient.IdentityPrivate)
		if err != nil {
			ui.Errorf("Context rename failed: %v", err)
			return
		}
		ui.Successf("Context renamed: %s (v%d)", ctx.DisplayName, ctx.MetadataVersion)

	case "add", "exclude", "remove", "include", "mute", "block":
		if len(args) < 3 {
			fmt.Printf("  Usage: context %s <context_id> <peer_id>\n", sub)
			return
		}
		ctxID := multimsg.ContextID(args[1])
		if _, err := state.Fanout.CtxStore.LoadContext(ctxID); err != nil {
			ui.Errorf("context %q does not exist — create it with 'context create', or list IDs with 'contexts'", args[1])
			return
		}
		peerID, err := state.ResolvePeer(args[2])
		if err != nil {
			ui.Errorf("%v", err)
			return
		}
		if err := ValidatePeerID(peerID); err != nil {
			ui.Errorf("invalid peer %q: %v", args[2], err)
			return
		}
		policy, ok := policyForSub(sub)
		if !ok {
			ui.Errorf("unknown policy action %q", sub)
			return
		}
		if err := state.Fanout.SetRecipientPolicy(ctxID, peerID, policy); err != nil {
			ui.Errorf("%s failed: %v", verbForSub(sub), err)
			return
		}
		switch policy {
		case multimsg.PolicyEnabled:
			ui.Successf("%s %s in context %s", verbForSub(sub), registry.ShortID(peerID), ctxID)
		default:
			ui.Successf("%s %s in context %s (%s)", verbForSub(sub), registry.ShortID(peerID), ctxID, policy.String())
		}

	case "members":
		if len(args) < 2 {
			fmt.Println("  Usage: context members <context_id>")
			return
		}
		printMembers(state.Fanout.CtxStore, multimsg.ContextID(args[1]))

	default:
		ui.Errorf("Unknown context subcommand: %s", sub)
	}
}

func policyForSub(sub string) (multimsg.RecipientPolicy, bool) {
	switch sub {
	case "add", "include":
		return multimsg.PolicyEnabled, true
	case "exclude", "remove":
		return multimsg.PolicyExcluded, true
	case "mute":
		return multimsg.PolicyMuted, true
	case "block":
		return multimsg.PolicyBlocked, true
	}
	return 0, false
}

func verbForSub(sub string) string {
	switch sub {
	case "add":
		return "Added"
	case "include":
		return "Re-enabled"
	case "exclude", "remove":
		return "Excluded"
	case "mute":
		return "Muted"
	case "block":
		return "Blocked"
	}
	return sub
}

func listContexts(store multimsg.ContextStore) {
	ctxs, err := store.ListContexts()
	if err != nil {
		ui.Errorf("Context list failed: %v", err)
		return
	}
	if len(ctxs) == 0 {
		ui.Infof("No contexts.")
		return
	}
	fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Contexts ❖"))
	for _, c := range ctxs {
		members, _ := store.ListPolicies(c.ContextID)
		active := 0
		for _, p := range members {
			if p.Policy == multimsg.PolicyEnabled || p.Policy == multimsg.PolicyMuted {
				active++
			}
		}
		fmt.Printf("  %s  v%d  %s  %s\n",
			ui.Info.Sprint(c.ContextID), c.MetadataVersion, c.DisplayName,
			ui.Comment.Sprintf("(%d member%s)", len(members), plural(len(members))))
		_ = active
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ValidatePeerID checks that id is a well-formed NexTalk peer ID (base58 of
// a 64-byte identity blob). Applied before storing recipient policies so a
// typo cannot silently poison a delivery set.
func ValidatePeerID(id string) error {
	if _, err := relay.PeerIDToEd25519Pub(id); err != nil {
		return fmt.Errorf("not a valid NexTalk peer ID (expected base58, 88 chars)")
	}
	return nil
}

func showContext(store multimsg.ContextStore, id multimsg.ContextID) {
	meta, err := store.LoadContext(id)
	if err != nil {
		ui.Errorf("context %q does not exist — create it with 'context create', or list IDs with 'contexts'", id)
		return
	}
	policies, _ := store.ListPolicies(id)
	printContextDetail(meta, policies)
}

func printContextDetail(meta *multimsg.MessageContext, policies []*multimsg.LocalRecipientPolicy) {
	fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Context: %s ❖", meta.DisplayName))
	fmt.Printf("  ID:      %s\n", meta.ContextID)
	fmt.Printf("  Version: %d\n", meta.MetadataVersion)
	fmt.Printf("  Creator: %s\n", meta.CreatorID)
	fmt.Printf("\n  Members:\n")
	if len(policies) == 0 {
		fmt.Println("    (none configured)")
	}
	for _, p := range policies {
		fmt.Printf("    %s %s  (%s)\n", PolicyIcon(p.Policy), registry.ShortID(p.Recipient), p.Policy.String())
	}
}

func printMembers(store multimsg.ContextStore, id multimsg.ContextID) {
	meta, err := store.LoadContext(id)
	if err != nil {
		ui.Errorf("context %q does not exist — list IDs with 'contexts'", id)
		return
	}
	policies, _ := store.ListPolicies(id)
	fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Members of %s ❖", meta.DisplayName))
	if len(policies) == 0 {
		fmt.Println("    (none configured)")
	}
	for _, p := range policies {
		fmt.Printf("    %s %s  [%s]\n", PolicyIcon(p.Policy), registry.ShortID(p.Recipient), p.Policy.String())
	}
}

// PolicyIcon returns the one-character status marker for a recipient policy.
func PolicyIcon(p multimsg.RecipientPolicy) string {
	switch p {
	case multimsg.PolicyEnabled:
		return "✓"
	case multimsg.PolicyMuted:
		return "~"
	case multimsg.PolicyBlocked:
		return "✗"
	case multimsg.PolicyExcluded:
		return "⊘"
	}
	return "?"
}

// ── send-multi ───────────────────────────────────────────────────────────────

func execSendMulti(state *registry.State, args []string) {
	if state.Fanout == nil || state.ActiveClient == nil {
		fmt.Println("  Please 'init' or 'load' an identity first.")
		return
	}
	if len(args) < 2 {
		fmt.Println("  Usage: send-multi <context_id> <message>")
		return
	}
	ctxRef := args[0]
	message := strings.Join(args[1:], " ")

	meta, policies, err := ResolveContextRef(state.Fanout.CtxStore, ctxRef)
	if err != nil {
		ui.Errorf("%v", err)
		return
	}
	var recipients []string
	for _, p := range policies {
		if p.Policy != multimsg.PolicyBlocked && p.Policy != multimsg.PolicyExcluded {
			recipients = append(recipients, p.Recipient)
		}
	}
	if len(recipients) == 0 {
		ui.Warnf("No enabled recipients in context %s", meta.DisplayName)
		return
	}

	result, err := state.Fanout.SendMultiMessage(state.Ctx, meta.ContextID, []byte(message), recipients)
	if err != nil {
		ui.Errorf("Multi-send failed: %v", err)
		return
	}

	fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ Multi-message: %s ❖", result.MessageID))
	fmt.Printf("  Context: %s (%s)\n", meta.DisplayName, meta.ContextID)
	fmt.Printf("\n  Deliveries:\n")
	for _, d := range result.Deliveries {
		icon := " "
		status := d.Status.String()
		switch d.Status {
		case multimsg.DeliverySent:
			icon = ui.Success.Sprint("✓")
			if state.Worker == nil {
				// No relay attached: "sent" means encrypted & exported below.
				status = "encrypted (export below)"
			}
		case multimsg.DeliveryPending:
			icon = ui.Warning.Sprint("~")
			status += " (no session)"
		case multimsg.DeliveryFailed:
			icon = ui.Fail.Sprint("✗")
			if d.Error != nil {
				status += ": " + d.Error.Error()
			}
		}
		fmt.Printf("    %s %s  %s\n", icon, registry.ShortID(d.Recipient), status)
	}
	// Precise verbs: with a relay the copies were transmitted; without one
	// they are only encrypted (and exported below).
	deliveredWord := "sent"
	if state.Worker == nil {
		deliveredWord = "encrypted"
	}
	fmt.Printf("\n  Summary: %d %s, %d pending, %d failed\n",
		result.SuccessCount(), deliveredWord, result.PendingCount(), result.FailedCount())

	// Export path for relay-less transports: every encrypted copy becomes a
	// self-describing transfer Container addressed to its recipient.
	if state.Worker == nil {
		exported := 0
		for _, d := range result.Deliveries {
			if d.Status != multimsg.DeliverySent || len(d.Ciphertext) == 0 {
				continue
			}
			container, err := frame.EncodeContainer(frame.TypeMultiMsg, d.Ciphertext)
			if err != nil {
				ui.Errorf("export for %s: %v", registry.ShortID(d.Recipient), err)
				continue
			}
			fmt.Printf("\n  %s DELIVER TO %s %s\n", ui.Warning.Sprint("▸"), ui.Info.Sprint(registry.ShortID(d.Recipient)), ui.Warning.Sprint("◂"))
			fmt.Println(string(container))
			exported++
		}
		if exported > 0 {
			ui.Infof("%d container(s) above — hand each to its recipient (paste, file, QR).", exported)
		}
	}

	// Record the outgoing message so the group thread stays complete locally.
	if state.MailboxStore != nil {
		if err := state.MailboxStore.AppendGroupOutgoing(
			string(meta.ContextID), meta.DisplayName, message); err != nil {
			ui.Warnf("Sent, but not recorded in mailbox: %v", err)
		}
	}
}

// resolveContext finds a context by exact ID first, then by display name,
// and returns it with its policies.
func ResolveContextRef(store multimsg.ContextStore, ref string) (*multimsg.MessageContext, []*multimsg.LocalRecipientPolicy, error) {
	meta, err := store.LoadContext(multimsg.ContextID(ref))
	if err != nil {
		// Display-name fallback so pasting a group name works everywhere.
		ctxs, lerr := store.ListContexts()
		if lerr == nil {
			for _, c := range ctxs {
				if strings.EqualFold(c.DisplayName, ref) {
					meta = c
					err = nil
					break
				}
			}
		}
		if err != nil {
			return nil, nil, fmt.Errorf("context %q does not exist — create it with 'context create', or list IDs with 'contexts'", ref)
		}
	}
	policies, _ := store.ListPolicies(meta.ContextID)
	return meta, policies, nil
}

func execContextsList(state *registry.State) {
	if state.Fanout == nil {
		fmt.Println("  Please 'init' or 'load' an identity first.")
		return
	}
	listContexts(state.Fanout.CtxStore)
}

// ── mailbox ──────────────────────────────────────────────────────────────────

func execMailbox(state *registry.State, args []string) {
	if state.MailboxStore == nil {
		ui.Errorf("Mailbox unavailable — init or load an identity first.")
		return
	}

	if len(args) == 0 {
		RenderMailboxList(state.MailboxStore)
		return
	}

	key, err := ResolveThreadKey(state, args[0])
	if err != nil {
		ui.Errorf("%v", err)
		return
	}

	msgs, err := state.MailboxStore.Read(key)
	if err != nil {
		ui.Warnf("%v", err)
		return
	}
	RenderThread(key, msgs)
}

// ── completion ───────────────────────────────────────────────────────────────

// CompleteContextArgs backs Tab completion for the `context` command:
//
//	context <Tab>                        → subcommand words
//	context create <Tab>                 → nothing (free-form name)
//	context show|members|... <Tab>       → context IDs + display names
//	context add|exclude|... <ctx> <Tab>  → peer IDs / contact aliases
func CompleteContextArgs(s *registry.State, typed []string, argIndex int, fragment string) []string {
	if argIndex <= 0 {
		return suffixCandidates(contextSubcommands, fragment)
	}
	sub := ""
	if argIndex-1 < len(typed) {
		sub = typed[argIndex-1]
	}

	switch sub {
	case "show", "rename", "add", "exclude", "remove", "include", "mute", "block", "members":
		if argIndex == 1 {
			return suffixCandidates(s.ContextCandidates(), fragment)
		}
		if argIndex == 2 && contextPeerSubcommands[sub] {
			return suffixCandidates(s.PeerCandidates(), fragment)
		}
	}
	return nil
}

// suffixCandidates filters candidates by prefix so both the shell completer
// and this hook behave identically for hand-filtered candidate sets.
func suffixCandidates(candidates []string, fragment string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if strings.HasPrefix(c, fragment) {
			out = append(out, c)
		}
	}
	return out
}
