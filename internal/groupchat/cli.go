// internal/groupchat/cli.go — the cobra face of the group-chat standard.
//
// Every transport mounts the SAME three commands (`context`, `send-multi`,
// `contexts`) plus `mailbox`, differing only in the Relay provider they
// inject. A nil/erroring Relay means deliveries are encrypted locally and
// exported as transfer Containers instead of transmitted — the offline and
// manual-proxy behavior.
package groupchat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal"
	"github.com/erfanheydarzade/NexTalk/internal/codec"
	"github.com/erfanheydarzade/NexTalk/internal/contacts"
	"github.com/erfanheydarzade/NexTalk/internal/frame"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

// CLIOptions parameterizes the shared commands for one transport.
type CLIOptions struct {
	// Relay builds the transport's live relay, or returns an error/nil when
	// the transport cannot transmit on its own (offline, manual proxy).
	Relay func() (relay.Relay, error)
}

// ── exported entry points (tests, scripts, transports without cobra) ────────

// RunContext executes one `context` subcommand against an identity's
// persisted stores.
func RunContext(localPeer string, args []string) error { return runContextCLI(localPeer, args) }

// RunSendMulti executes a full fan-out request.
func RunSendMulti(req SendMultiRequest) error { return runSendMultiCLI(req) }

// RunMailbox lists or reads one conversation from the persistent mailbox.
func RunMailbox(localPeer string, args []string) error {
	store, err := mailbox.Load(localPeer)
	if err != nil {
		return fmt.Errorf("open mailbox: %w", err)
	}
	if len(args) == 0 {
		RenderMailboxList(store)
		return nil
	}
	key := args[0]
	if resolved, rerr := store.ResolveThread(key); rerr == nil {
		key = resolved
	} else if !plausiblyPeerID(key) {
		return fmt.Errorf("%q matches no group; pass a full peer ID for direct messages", key)
	}
	msgs, err := store.Read(key)
	if err != nil {
		return err
	}
	RenderThread(key, msgs)
	return nil
}

// ── context ──────────────────────────────────────────────────────────────────

// ContextCLI builds `nextalk <transport> context`.
func ContextCLI(opts CLIOptions) *cobra.Command {
	var localPeer string
	var format string

	cmd := &cobra.Command{
		Use:   "context <create|list|show|rename|add|exclude|remove|include|mute|block|members> [args...]",
		Short: "Manage multi-message contexts (groups)",
		Long: "Create and manage multi-message contexts for the fan-out layer.\n" +
			"Identical semantics in every transport and in the interactive shell.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runContextCLI(localPeer, args)
			return reportExit(err, format)
		},
		ValidArgsFunction: completeContextArgsCLI,
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}

func runContextCLI(localPeer string, args []string) error {
	sub := args[0]

	cl, err := Client.LoadClient(localPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	store, _, err := multimsg.OpenIdentityStores(localPeer)
	if err != nil {
		return fmt.Errorf("open stores: %w", err)
	}

	switch sub {
	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: context create <name>")
		}
		meta, err := newContextFor(store, cl, strings.Join(args[1:], " "))
		if err != nil {
			return err
		}
		fmt.Printf("%s  v%d  %s\n", meta.ContextID, meta.MetadataVersion, meta.DisplayName)
		return nil

	case "list", "ls":
		ctxs, err := store.ListContexts()
		if err != nil {
			return err
		}
		if len(ctxs) == 0 {
			fmt.Println("[i] No contexts.")
			return nil
		}
		for _, m := range ctxs {
			fmt.Printf("%s  v%d  %s\n", m.ContextID, m.MetadataVersion, m.DisplayName)
		}
		return nil

	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: context show <context_id>")
		}
		meta, _, err := ResolveContextRef(store, args[1])
		if err != nil {
			return err
		}
		policies, _ := store.ListPolicies(meta.ContextID)
		fmt.Printf("\n❖ Context: %s ❖\n  ID:      %s\n  Version: %d\n  Creator: %s\n\n  Members:\n",
			meta.DisplayName, meta.ContextID, meta.MetadataVersion, meta.CreatorID)
		if len(policies) == 0 {
			fmt.Println("    (none configured)")
		}
		for _, p := range policies {
			fmt.Printf("    [%s] %s (%s)\n", PolicyIcon(p.Policy), p.Recipient, p.Policy.String())
		}
		return nil

	case "rename":
		if len(args) < 3 {
			return fmt.Errorf("usage: context rename <context_id> <new_name>")
		}
		fan := multimsg.NewFanout(cl, nil, store, nil, multimsg.DefaultFanoutConfig())
		newName := strings.Join(args[2:], " ")
		meta, err := fan.UpdateContext(multimsg.ContextID(args[1]), newName, cl.IdentityPrivate)
		if err != nil {
			return err
		}
		fmt.Printf("[✓] Renamed to %q (v%d)\n", meta.DisplayName, meta.MetadataVersion)
		return nil

	case "add", "exclude", "remove", "include", "mute", "block":
		if len(args) < 3 {
			return fmt.Errorf("usage: context %s <context_id> <peer_id>", sub)
		}
		if _, err := store.LoadContext(multimsg.ContextID(args[1])); err != nil {
			return fmt.Errorf("context %q does not exist — create it with 'context create', or list IDs with 'contexts'", args[1])
		}
		if err := ValidatePeerID(args[2]); err != nil {
			return fmt.Errorf("invalid peer %q: %v", args[2], err)
		}
		policy, ok := policyForSub(sub)
		if !ok {
			return fmt.Errorf("unknown policy action %q", sub)
		}
		lp := &multimsg.LocalRecipientPolicy{
			ContextID: multimsg.ContextID(args[1]),
			Recipient: args[2],
			Policy:    policy,
		}
		if err := store.SavePolicy(lp); err != nil {
			return fmt.Errorf("set policy: %w", err)
		}
		fmt.Printf("[✓] %s is now %s in %s\n", shortDisplay(args[2]), policy.String(), shortDisplay(args[1]))
		return nil

	case "members":
		if len(args) < 2 {
			return fmt.Errorf("usage: context members <context_id>")
		}
		meta, policies, err := ResolveContextRef(store, args[1])
		if err != nil {
			return err
		}
		_ = meta
		if len(policies) == 0 {
			fmt.Println("    (no members configured)")
			return nil
		}
		for _, p := range policies {
			fmt.Printf("    [%s] %s (%s)\n", PolicyIcon(p.Policy), p.Recipient, p.Policy.String())
		}
		return nil

	default:
		return fmt.Errorf("unknown context subcommand %q (want %s)", sub, strings.Join(contextSubcommands, "|"))
	}
}

// newContextFor signs and stores a fresh context under cl's identity.
func newContextFor(store multimsg.ContextStore, cl *Client.Client, name string) (*multimsg.MessageContext, error) {
	tmp := multimsg.NewFanout(cl, nil, store, nil, multimsg.DefaultFanoutConfig())
	return tmp.CreateContext(name, cl.IdentityPrivate)
}

// ── send-multi ───────────────────────────────────────────────────────────────

// SendMultiCLI builds `nextalk <transport> send-multi`.
func SendMultiCLI(opts CLIOptions) *cobra.Command {
	var localPeer, ctxRef, message, inputFile, inputEncoding, outputDir, format string

	cmd := &cobra.Command{
		Use:   "send-multi",
		Short: "Encrypt one copy per member of a context",
		Long: "Fan out a multi-recipient message through each member's established\n" +
			"1:1 secure session. With a live relay the copies are transmitted;\n" +
			"without one, each copy is written as a transfer container for\n" +
			"manual delivery (--output-dir).",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runSendMultiCLI(SendMultiRequest{
				LocalPeer:     localPeer,
				CtxRef:        ctxRef,
				Message:       message,
				InputFile:     inputFile,
				InputEncoding: inputEncoding,
				OutputDir:     outputDir,
				Format:        format,
				Relay:         opts.Relay,
			})
			return reportExit(err, format)
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return FilterByPrefix(ContextCandidates(flagString(cmd, "id")), toComplete),
					cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVarP(&ctxRef, "context", "c", "", "Target context ID or display name")
	cmd.Flags().StringVarP(&message, "message", "m", "", "Message text (inline)")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Path to plaintext input file")
	cmd.Flags().StringVar(&inputEncoding, "in", string(codec.EncodingRaw), "Input encoding (raw,b64,hex)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Write one container file per recipient here (relay-less transports)")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("context")

	return cmd
}

// SendMultiRequest carries everything the shared send-multi implementation
// needs; both the cobra builder and tests use it directly.
type SendMultiRequest struct {
	LocalPeer     string
	CtxRef        string
	Message       string
	InputFile     string
	InputEncoding string
	OutputDir     string
	Format        string
	Relay         func() (relay.Relay, error)
}

func runSendMultiCLI(req SendMultiRequest) error {
	if req.Format == "" {
		req.Format = formatHuman // programmatic callers omit the flag
	}
	if err := validateFormatStr(req.Format); err != nil {
		return err
	}

	cl, err := Client.LoadClient(req.LocalPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	var r relay.Relay // nil ⇒ export containers instead of transmitting
	if req.Relay != nil {
		r, err = req.Relay()
		if err != nil {
			return fmt.Errorf("relay: %w", err)
		}
	}

	ctxStore, deliveryStore, err := multimsg.OpenIdentityStores(req.LocalPeer)
	if err != nil {
		return fmt.Errorf("open stores: %w", err)
	}
	fan := multimsg.NewFanout(cl, r, ctxStore, deliveryStore, multimsg.DefaultFanoutConfig())

	meta, policies, err := ResolveContextRef(ctxStore, req.CtxRef)
	if err != nil {
		return err
	}

	var recipients []string
	for _, p := range policies {
		if p.Policy != multimsg.PolicyBlocked && p.Policy != multimsg.PolicyExcluded {
			recipients = append(recipients, p.Recipient)
		}
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no enabled recipients in %s — add some with 'context add'", meta.DisplayName)
	}

	plaintext, err := readPayloadStdin(req.Message, req.InputFile, req.InputEncoding)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}
	body := strings.TrimRight(string(plaintext), "\n")

	result, err := fan.SendMultiMessage(context.Background(), meta.ContextID, plaintext, recipients)
	if err != nil {
		return fmt.Errorf("multi-send: %w", err)
	}

	if store, err := mailbox.Load(req.LocalPeer); err == nil {
		if err := store.AppendGroupOutgoing(string(meta.ContextID), meta.DisplayName, body); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Sent, but not recorded in mailbox: %v\n", err)
		}
	}

	if req.Format == formatJSON {
		return writeJSONValue(result)
	}

	fmt.Printf("\n❖ Multi-message: %s ❖\n", result.MessageID)
	fmt.Printf("  Context: %s (%s)\n\n  Deliveries:\n", meta.DisplayName, meta.ContextID)

	exported := 0
	for _, d := range result.Deliveries {
		icon, status := " ", d.Status.String()
		switch d.Status {
		case multimsg.DeliverySent:
			icon = "✓"
			if r == nil {
				status = "encrypted (export below)"
			}
		case multimsg.DeliveryPending:
			icon = "~"
			status += " (no session)"
		case multimsg.DeliveryFailed:
			icon = "✗"
			if d.Error != nil {
				status += ": " + d.Error.Error()
			}
		}
		fmt.Printf("    %s %s  %s\n", icon, d.Recipient, status)
	}
	fmt.Printf("\n  Summary: %d encrypted, %d pending, %d failed\n",
		result.SuccessCount(), result.PendingCount(), result.FailedCount())

	// Relay-less export: per-recipient containers, to stdout or --output-dir.
	if r == nil {
		for _, d := range result.Deliveries {
			if d.Status != multimsg.DeliverySent || len(d.Ciphertext) == 0 {
				continue
			}
			container, err := frame.EncodeContainer(frame.TypeMultiMsg, d.Ciphertext)
			if err != nil {
				return fmt.Errorf("container for %s: %w", d.Recipient, err)
			}
			if req.OutputDir != "" {
				if err := os.MkdirAll(req.OutputDir, 0700); err != nil {
					return fmt.Errorf("output dir: %w", err)
				}
				name := fmt.Sprintf("%s.%s.container.json", shortDisplay(string(result.MessageID)), shortDisplay(d.Recipient))
				path := req.OutputDir + string(os.PathSeparator) + name
				if err := os.WriteFile(path, container, 0600); err != nil {
					return fmt.Errorf("write %s: %w", path, err)
				}
				fmt.Printf("  ▸ %s → %s\n", registry.ShortID(d.Recipient), path)
				exported++
			} else {
				fmt.Printf("\n  ▸ DELIVER TO %s ◂\n%s\n", registry.ShortID(d.Recipient), container)
				exported++
			}
		}
		if exported > 0 {
			fmt.Printf("\n[i] %d container(s) — hand each to its recipient.\n", exported)
		}
	}
	return nil
}

// ── contexts / mailbox ───────────────────────────────────────────────────────

// ContextsCLI builds `nextalk <transport> contexts`.
func ContextsCLI(opts CLIOptions) *cobra.Command {
	var localPeer string
	var format string

	cmd := &cobra.Command{
		Use:           "contexts",
		Short:         "List all multi-message contexts for an identity",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := func() error {
				store, _, err := multimsg.OpenIdentityStores(localPeer)
				if err != nil {
					return fmt.Errorf("open stores: %w", err)
				}
				ctxs, err := store.ListContexts()
				if err != nil {
					return err
				}
				if format == formatJSON {
					type row struct {
						ContextID   string `json:"context_id"`
						DisplayName string `json:"display_name"`
						Version     uint64 `json:"version"`
						Creator     string `json:"creator"`
					}
					out := make([]row, 0, len(ctxs))
					for _, m := range ctxs {
						out = append(out, row{
							ContextID:   string(m.ContextID),
							DisplayName: m.DisplayName,
							Version:     m.MetadataVersion,
							Creator:     m.CreatorID,
						})
					}
					return writeJSONValue(out)
				}
				if len(ctxs) == 0 {
					fmt.Println("[i] No contexts.")
					return nil
				}
				fmt.Println("\n❖ Contexts ❖")
				for _, m := range ctxs {
					fmt.Printf("  %s  v%d  %s\n", m.ContextID, m.MetadataVersion, m.DisplayName)
				}
				return nil
			}()
			return reportExit(err, format)
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// MailboxCLI builds `nextalk <transport> mailbox`.
func MailboxCLI(opts CLIOptions) *cobra.Command {
	var localPeer string
	var format string

	cmd := &cobra.Command{
		Use:           "mailbox [peer|group]",
		Short:         "List stored conversations, or read one peer/group thread",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := func() error {
				store, err := mailbox.Load(localPeer)
				if err != nil {
					return fmt.Errorf("open mailbox: %w", err)
				}
				if len(args) == 0 {
					RenderMailboxList(store)
					return nil
				}
				key := args[0]
				if resolved, rerr := store.ResolveThread(key); rerr == nil {
					key = resolved
				} else if !plausiblyPeerID(key) {
					return fmt.Errorf("%q matches no group; pass a full peer ID for direct messages", key)
				}
				msgs, err := store.Read(key)
				if err != nil {
					return err
				}
				RenderThread(key, msgs)
				return nil
			}()
			return reportExit(err, format)
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			localID := flagString(cmd, "id")
			candidates := append(PeerCandidates(localID), ContextCandidates(localID)...)
			return FilterByPrefix(candidates, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// ── completion & tiny helpers shared by the builders ────────────────────────

// completeContextArgsCLI backs cobra completion for the `context` command.
func completeContextArgsCLI(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	localPeer := flagString(cmd, "id")

	if len(args) == 0 {
		return FilterByPrefix(contextSubcommands, toComplete), cobra.ShellCompDirectiveNoFileComp
	}

	sub := args[0]
	switch sub {
	case "show", "rename", "add", "exclude", "remove", "include", "mute", "block", "members":
		switch len(args) {
		case 1:
			return FilterByPrefix(ContextCandidates(localPeer), toComplete), cobra.ShellCompDirectiveNoFileComp
		case 2:
			if contextPeerSubcommands[sub] {
				return FilterByPrefix(PeerCandidates(localPeer), toComplete), cobra.ShellCompDirectiveNoFileComp
			}
		}
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// ContextCandidates loads every known context ID and display name for an
// identity. Best-effort: any failure yields no candidates, never an error.
func ContextCandidates(localPeer string) []string {
	if localPeer == "" {
		return nil
	}
	store, _, err := multimsg.OpenIdentityStores(localPeer)
	if err != nil {
		return nil
	}
	ctxs, err := store.ListContexts()
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(ctxs)*2)
	for _, c := range ctxs {
		set[string(c.ContextID)] = true
		if c.DisplayName != "" {
			set[c.DisplayName] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PeerCandidates unions the identity's established sessions with the global
// contacts book.
func PeerCandidates(localPeer string) []string {
	set := make(map[string]bool)

	if localPeer != "" {
		if cl, err := Client.LoadClient(localPeer); err == nil {
			for id := range cl.Sessions {
				if strings.HasPrefix(id, "pending") {
					continue
				}
				set[id] = true
			}
		}
	}
	if book, err := contacts.Load(); err == nil {
		for name, c := range book.Contacts {
			if name != "" {
				set[name] = true
			}
			if c.UserID != "" {
				set[c.UserID] = true
			}
		}
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FilterByPrefix keeps candidates whose prefix matches what the user typed.
// Exported so transport-local completions reuse the same matching rule.
func FilterByPrefix(candidates []string, toComplete string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if strings.HasPrefix(c, toComplete) {
			out = append(out, c)
		}
	}
	return out
}

func flagString(cmd *cobra.Command, name string) string {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

func plausiblyPeerID(arg string) bool {
	return len(arg) >= 32 && !strings.ContainsAny(arg, " \t")
}

const (
	formatHuman = "human"
	formatJSON  = "json"
)

func validateFormatStr(format string) error {
	switch format {
	case formatHuman, formatJSON:
		return nil
	default:
		return fmt.Errorf("invalid format %q (want human or json)", format)
	}
}

func reportExit(err error, format string) error {
	if err == nil {
		return nil
	}
	if format != formatJSON {
		fmt.Fprintf(os.Stderr, "[✗] %v\n", err)
		return internal.WrapReported(err)
	}
	if writeErr := writeJSONValue(struct {
		Error string `json:"error"`
	}{err.Error()}); writeErr == nil {
		return internal.WrapReported(err)
	}
	// JSON output itself failed — fall back to stderr so the user still
	// learns what happened.
	fmt.Fprintf(os.Stderr, "[✗] %v\n", err)
	return internal.WrapReported(err)
}

func writeJSONValue(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(data); err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte{'\n'})
	return err
}

// readPayloadStdin mirrors the CLI payload convention used across NexTalk:
// inline value, then file, then stdin — decoded per encoding.
func readPayloadStdin(inline, inputFile, inputEncoding string) ([]byte, error) {
	var raw []byte

	switch {
	case inputFile != "":
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		raw = data

	case inline != "":
		raw = []byte(inline)

	default:
		fi, err := os.Stdin.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat stdin: %w", err)
		}
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no input provided: pass -m/-f, or pipe data via stdin")
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("no input provided")
		}
		raw = data
	}

	decoded, err := codec.DecodeInput(inputEncoding, raw)
	if err != nil {
		return nil, fmt.Errorf("decode input as %s: %w", inputEncoding, err)
	}
	return decoded, nil
}

func shortDisplay(id string) string {
	if len(id) > 12 {
		return id[:9] + "..."
	}
	return id
}
