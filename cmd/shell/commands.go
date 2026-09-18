// Command tree for the unified NexTalk shell.
//
// Every entry here is a thin adapter over internal/transportops — the same
// functions the one-shot cobra CLI calls. The shell is just another
// frontend: no transport, crypto, or storage logic lives in this file.
//
// Positional transport IDs fall back to the session relay (`use relay`);
// -i/--id falls back to the session identity (`use identity`). Secrets are
// never flags here when the shell can prompt for hidden input instead.
package shell

import (
	"fmt"
	"sort"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/registry"

	"github.com/erfanheydarzade/NexTalk/internal/buildinfo"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	"github.com/erfanheydarzade/NexTalk/internal/transportops"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// shellArgKind mirrors registry.ArgKind for completion without importing
// per-transport specs: these commands declare their own slots.
const (
	argText = iota
	argPeer
	argIdentity
	argThread
	argContext
	argFile
	argTransport
)

// transportFlag returns the standard transport-positional help used by
// commands that default to the session relay.
func transportArgs() string { return "[transport]" }

// depsFor builds transportops.Deps for one command invocation.
func depsFor(ctx *shellcmd.Context) *transportops.Deps {
	s := ctx.Session
	var dir string
	interactive := true
	if s != nil {
		dir = s.TransportsDir
		interactive = s.Interactive
	}
	d := &transportops.Deps{
		TransportsDir: dir,
		Stdout:        ctx.Stdout,
		Stderr:        ctx.Stderr,
		JSON:          ctx.JSON(),
		ShowSecrets:   ctx.ShowSecrets(),
		Session:       s,
	}
	if interactive {
		d.PromptSecret = promptSecret
		d.Confirm = promptConfirm
	} else if s != nil {
		d.Confirm = func(prompt string) (bool, error) {
			fmt.Fprintln(ctx.Stderr, "(non-interactive: confirmed automatically)")
			return true, nil
		}
	}
	return d
}

// relayOrSession resolves the optional transport positional.
func relayOrSession(ctx *shellcmd.Context) (string, error) {
	if len(ctx.Args) > 0 && ctx.Args[0] != "" {
		return ctx.Args[0], nil
	}
	if ctx.Session != nil && ctx.Session.Relay != "" {
		return ctx.Session.Relay, nil
	}
	return "", fmt.Errorf("no transport: pass one or `use relay` first")
}

// relayAndTicket splits recv positionals into an optional transport and an
// optional bare ticket: [transport] [ticket], [ticket], or []. A single
// word is a ticket when the session already has a relay, else a transport.
func relayAndTicket(ctx *shellcmd.Context) (string, []string, error) {
	switch len(ctx.Args) {
	case 0:
		id, err := relayOrSession(ctx)
		return id, nil, err
	case 1:
		if ctx.Session != nil && ctx.Session.Relay != "" {
			return ctx.Session.Relay, ctx.Args, nil
		}
		return ctx.Args[0], nil, nil
	default:
		return ctx.Args[0], ctx.Args[1:], nil
	}
}

// identityOrSession resolves -i/--id with session fallback.
func identityOrSession(ctx *shellcmd.Context) (string, error) {
	if id := ctx.Get("id"); id != "" {
		return id, nil
	}
	if ctx.Session != nil && ctx.Session.Identity != "" {
		return ctx.Session.Identity, nil
	}
	return "", fmt.Errorf("no identity: pass -i/--id or `use identity` first")
}

// buildRegistry assembles the full unified command tree.
func buildRegistry() *shellcmd.Registry {
	r := shellcmd.NewRegistry()
	submit := func(path string, c *shellcmd.Command) {
		r.Register(strings.Fields(path), c)
	}

	// ---- transport group (mirrors `nextalk transport ...`) ----
	tf := func(name, short, argsUsage string, flags []shellcmd.Flag, run func(*shellcmd.Context) error) *shellcmd.Command {
		return &shellcmd.Command{Name: name, Short: short, ArgsUsage: argsUsage, Flags: flags, Run: run}
	}
	submit("transport list", tf("list", "List installed transports", "", nil,
		func(ctx *shellcmd.Context) error {
			_, err := transportops.List(depsFor(ctx))
			return err
		}))
	submit("transport install", tf("install", "Install a transport package (.ntx)", "<package.ntx>", []shellcmd.Flag{
		{Name: "enable", Usage: "enable immediately after install", IsBool: true},
	}, func(ctx *shellcmd.Context) error {
		if err := ctx.Need(0, "package path"); err != nil {
			return err
		}
		return transportops.Install(depsFor(ctx), ctx.Args[0], ctx.Bool("enable"))
	}))
	submit("transport remove", tf("remove", "Remove an installed transport", "<id>", nil,
		func(ctx *shellcmd.Context) error {
			if err := ctx.Need(0, "transport id"); err != nil {
				return err
			}
			return transportops.Remove(depsFor(ctx), ctx.Args[0])
		}))
	submit("transport enable", tf("enable", "Enable an installed transport", "<id>", nil,
		func(ctx *shellcmd.Context) error {
			if err := ctx.Need(0, "transport id"); err != nil {
				return err
			}
			return transportops.Enable(depsFor(ctx), ctx.Args[0])
		}))
	submit("transport disable", tf("disable", "Disable a transport (stops it if running)", "<id>", nil,
		func(ctx *shellcmd.Context) error {
			if err := ctx.Need(0, "transport id"); err != nil {
				return err
			}
			return transportops.Disable(depsFor(ctx), ctx.Args[0])
		}))
	submit("transport status", tf("status", "Show transport status", "[id]", nil,
		func(ctx *shellcmd.Context) error {
			id := ""
			if len(ctx.Args) > 0 {
				id = ctx.Args[0]
			}
			return transportops.Status(depsFor(ctx), id)
		}))
	submit("transport config", tf("config", "Store an opaque config blob applied at next start", "<id> <json>", nil,
		func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 2 {
				return fmt.Errorf("usage: transport config <id> <json>")
			}
			return transportops.SetConfig(depsFor(ctx), ctx.Args[0], ctx.Args[1])
		}))
	submit("transport attach", tf("attach", "Subscribe a mailbox for polling (stores a bearer, never a key)", "<id>", []shellcmd.Flag{
		{Name: "mailbox", Usage: "Mailbox ID, 32 lowercase hex", Required: true},
		{Name: "secret", Usage: "Read secret, 64 hex (prompts hidden when omitted)"},
		{Name: "shard", Usage: "Shard URL", Required: true},
		{Name: "router", Usage: "Router URL"},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		return transportops.Attach(depsFor(ctx), transportops.AttachParams{
			TransportID: id, MailboxID: ctx.Get("mailbox"), ReadSecret: ctx.Get("secret"),
			ShardURL: ctx.Get("shard"), RouterURL: ctx.Get("router"),
		})
	}))
	submit("transport detach", tf("detach", "Unsubscribe a mailbox", "<id>", []shellcmd.Flag{
		{Name: "mailbox", Usage: "Mailbox ID", Required: true},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		return transportops.Detach(depsFor(ctx), id, ctx.Get("mailbox"))
	}))
	submit("transport poll", tf("poll", "Poll a transport and dispatch incoming frames", "[transport]", []shellcmd.Flag{
		{Name: "id", Short: "i", Usage: "Local peer ID (defaults to session identity)"},
		{Name: "mailbox", Usage: "Only poll this mailbox id (hex)"},
		{Name: "limit", Usage: "Max frames per mailbox", Default: "32"},
		{Name: "format", Usage: "Output format: human, json", Default: "human"},
		{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		limit := 32
		if v := ctx.Get("limit"); v != "" {
			if _, err := fmt.Sscanf(v, "%d", &limit); err != nil {
				return fmt.Errorf("bad --limit %q", v)
			}
		}
		identity, err := identityOrSession(ctx)
		if err != nil {
			return err
		}
		return transportops.Poll(depsFor(ctx), transportops.PollParams{
			TransportID: id, Identity: identity,
			Mailbox: ctx.Get("mailbox"), Limit: limit, Format: ctx.Get("format"),
		})
	}))
	submit("transport send-frame", tf("send-frame", "Deliver one already-encrypted frame file", "[transport]", []shellcmd.Flag{
		{Name: "to", Usage: "Recipient peer ID or 64-hex Ed25519 pubkey"},
		{Name: "mailbox", Usage: "Explicit recipient mailbox, 32 hex"},
		{Name: "shard", Usage: "Shard URL for --mailbox"},
		{Name: "file", Short: "f", Usage: "Frame file", Required: true},
		{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		return transportops.SendFrame(depsFor(ctx), transportops.SendFrameParams{
			TransportID: id, Peer: ctx.Get("to"),
			MailboxID: ctx.Get("mailbox"), ShardURL: ctx.Get("shard"), File: ctx.Get("file"),
		})
	}))
	submit("transport register-identity", tf("register-identity", "Register the active identity's pubkey with the Router (required for peer messaging)", "[transport]", []shellcmd.Flag{
		{Name: "router", Usage: "Router URL (optional when `transport config` is set)"},
		{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		{Name: "show-secrets", Usage: "Print secrets verbatim (redacted otherwise)", IsBool: true},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		// identity="" -> IdentityRegister falls back to d.Session.Identity
		_, err = transportops.IdentityRegister(depsFor(ctx), id, "", ctx.Get("router"))
		return err
	}))
	submit("transport xfer-register", tf("xfer-register", "Mint a file-transfer mailbox (scoped credential; not identity registration)", "[transport]", []shellcmd.Flag{
		{Name: "router", Usage: "Router URL (optional when `transport config` is set)"},
		{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		{Name: "show-secrets", Usage: "Print secrets verbatim (redacted otherwise)", IsBool: true},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		// identity="" -> FilerelayRegister falls back to d.Session.Identity
		return transportops.FilerelayRegister(depsFor(ctx), id, "", ctx.Get("router"))
	}))
	submit("transport resolve", tf("resolve", "Resolve a recipient to mailbox + shard", "[transport]", []shellcmd.Flag{
		{Name: "to", Usage: "Recipient peer ID or 64-hex pubkey", Required: true},
		{Name: "router", Usage: "Router URL", Required: true},
		{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
	}, func(ctx *shellcmd.Context) error {
		id, err := relayOrSession(ctx)
		if err != nil {
			return err
		}
		return transportops.FilerelayResolve(depsFor(ctx), id, ctx.Get("to"), ctx.Get("router"))
	}))

	// ---- xfer group ----
	submit("xfer send", &shellcmd.Command{
		Name: "send", Aliases: []string{"upload"},
		Short:     "Encrypt a file end-to-end and upload it in chunks",
		ArgsUsage: "[transport]",
		Flags: []shellcmd.Flag{
			{Name: "id", Short: "i", Usage: "Local peer ID (defaults to session identity)"},
			{Name: "to", Usage: "Recipient peer ID (required, needs a session)"},
			{Name: "mailbox", Usage: "Explicit mailbox, 32 hex: recipient address, or OWN mailbox for ticket shares"},
			{Name: "shard", Usage: "Shard URL for --mailbox"},
			{Name: "file", Short: "f", Usage: "File to send", Required: true},
			{Name: "chunk-size", Usage: "Chunk size in bytes", Default: "32768"},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			id, err := relayOrSession(ctx)
			if err != nil {
				return err
			}
			identity, err := identityOrSession(ctx)
			if err != nil {
				return err
			}
			if ctx.Get("to") == "" {
				return fmt.Errorf("missing --to (recipient peer ID)")
			}
			chunkSize := 32768
			if v := ctx.Get("chunk-size"); v != "" {
				if _, err := fmt.Sscanf(v, "%d", &chunkSize); err != nil {
					return fmt.Errorf("bad --chunk-size %q", v)
				}
			}
			return transportops.XferSend(depsFor(ctx), transportops.XferSendParams{
				TransportID: id, Identity: identity, Peer: ctx.Get("to"),
				MailboxID: ctx.Get("mailbox"), ShardURL: ctx.Get("shard"),
				File: ctx.Get("file"), ChunkSize: chunkSize,
			})
		},
	})
	submit("xfer recv", &shellcmd.Command{
		Name: "recv", Aliases: []string{"download"},
		Short:     "Download, verify and decrypt a file transfer",
		ArgsUsage: "[transport] [ticket]",
		Flags: []shellcmd.Flag{
			{Name: "id", Short: "i", Usage: "Local peer ID (defaults to session identity)"},
			{Name: "from", Usage: "Expected sender peer ID"},
			{Name: "ticket", Usage: "Ticket base64 (ticket mode)"},
			{Name: "transfer", Usage: "Transfer ID, 32 hex (mailbox mode)"},
			{Name: "mailbox", Usage: "Recipient mailbox ID, 32 hex (mailbox mode)"},
			{Name: "secret", Usage: "Read secret, 64 hex (mailbox mode; prompts hidden when omitted)"},
			{Name: "shard", Usage: "Shard URL"},
			{Name: "manifest", Usage: "Transfer manifest, base64 (mailbox mode)"},
			{Name: "out", Short: "o", Usage: "Output file", Required: true},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			id, args, err := relayAndTicket(ctx)
			if err != nil {
				return err
			}
			identity, err := identityOrSession(ctx)
			if err != nil {
				return err
			}
			ticket := ctx.Get("ticket")
			if ticket == "" && len(args) > 0 {
				// Bare positional ticket: `xfer recv BgEB... -o out`.
				ticket = args[0]
			}
			return transportops.XferRecv(depsFor(ctx), transportops.XferRecvParams{
				TransportID: id, Identity: identity, Peer: ctx.Get("from"),
				TicketB64: ticket, TransferID: ctx.Get("transfer"),
				MailboxID: ctx.Get("mailbox"), Secret: ctx.Get("secret"),
				ShardURL: ctx.Get("shard"), ManifestB64: ctx.Get("manifest"), Out: ctx.Get("out"),
			})
		},
	})
	submit("xfer resume", &shellcmd.Command{
		Name: "resume", Short: "Show transfer progress without downloading",
		ArgsUsage: "[transport]",
		Flags: []shellcmd.Flag{
			{Name: "transfer", Usage: "Transfer ID, 32 hex chars (mailbox mode; inside ticket otherwise)"},
			{Name: "mailbox", Usage: "Mailbox ID, 32 hex (mailbox mode)"},
			{Name: "secret", Usage: "Read secret, 64 hex (mailbox mode; prompts hidden when omitted)"},
			{Name: "ticket", Usage: "Ticket base64 (ticket mode)"},
			{Name: "shard", Usage: "Shard URL (ticket mode)"},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			id, err := relayOrSession(ctx)
			if err != nil {
				return err
			}
			return transportops.XferResume(depsFor(ctx), transportops.XferResumeParams{
				TransportID: id, TransferID: ctx.Get("transfer"), MailboxID: ctx.Get("mailbox"),
				Secret: ctx.Get("secret"), TicketB64: ctx.Get("ticket"), ShardURL: ctx.Get("shard"),
			})
		},
	})
	submit("xfer cancel", &shellcmd.Command{
		Name: "cancel", Short: "Abort a transfer (mailbox owner only; tickets never cancel)",
		ArgsUsage: "[transport]",
		Flags: []shellcmd.Flag{
			{Name: "transfer", Usage: "Transfer ID, 32 hex chars", Required: true},
			{Name: "mailbox", Usage: "Mailbox ID, 32 hex", Required: true},
			{Name: "secret", Usage: "Read secret, 64 hex (prompts hidden when omitted)"},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			id, err := relayOrSession(ctx)
			if err != nil {
				return err
			}
			return transportops.XferCancel(depsFor(ctx), transportops.XferCancelParams{
				TransportID: id, TransferID: ctx.Get("transfer"),
				MailboxID: ctx.Get("mailbox"), Secret: ctx.Get("secret"),
			})
		},
	})
	submit("xfer inspect", &shellcmd.Command{
		Name: "inspect", Short: "Decode a ticket offline (no network): who, what, where",
		ArgsUsage: "[ticket]",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
			{Name: "show-secrets", Usage: "Print the download secret verbatim", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			ticket := ""
			if len(ctx.Args) > 0 {
				ticket = ctx.Args[0]
			}
			if ticket == "" {
				return fmt.Errorf("pass a ticket base64 argument")
			}
			return transportops.XferInspect(depsFor(ctx), ticket)
		},
	})
	submit("xfer list", &shellcmd.Command{
		Name: "list", Short: "List transfers created in this session",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			refs := []shellcmd.TransferRef{}
			if ctx.Session != nil {
				refs = ctx.Session.Transfers
			}
			if d.JSON {
				return d.JSONOut(map[string]any{"transfers": refs})
			}
			if len(refs) == 0 {
				d.Human("No transfers this session. Run `xfer send`.")
				return nil
			}
			for _, t := range refs {
				d.Human("  %s  %s (%d bytes)", t.ID, t.File, t.Size)
			}
			return nil
		},
	})

	// ---- relay group (message-relay diagnostics) ----
	submit("relay list", &shellcmd.Command{
		Name: "list", Short: "List installed message-capable transports",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			_, err := transportops.RelayList(depsFor(ctx))
			return err
		},
	})
	submit("relay ping", &shellcmd.Command{
		Name: "ping", Short: "Start (if enabled) and status-check a transport",
		ArgsUsage: "[transport]",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			id, err := relayOrSession(ctx)
			if err != nil {
				return err
			}
			return transportops.RelayPing(depsFor(ctx), id)
		},
	})
	submit("relay info", &shellcmd.Command{
		Name: "info", Short: "Show a transport's manifest and runtime state (no secrets)",
		ArgsUsage: "[transport]",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			id, err := relayOrSession(ctx)
			if err != nil {
				return err
			}
			return transportops.RelayInfo(depsFor(ctx), id)
		},
	})

	// ---- message group ----
	submit("message send", &shellcmd.Command{
		Name: "send", Short: "Encrypt a message and deliver it through the active relay",
		ArgsUsage: "<peer> <text...>",
		Args:      []registry.ArgKind{registry.ArgPeer}, Variadic: registry.ArgText,
		Flags: []shellcmd.Flag{
			{Name: "id", Short: "i", Usage: "Local peer ID (defaults to session identity)"},
			{Name: "via", Usage: "Transport ID (defaults to session relay)"},
			{Name: "ticket", Usage: "Ticket base64 appended as its own line"},
			{Name: "mailbox", Usage: "Explicit recipient mailbox, 32 hex (address-shared transports)"},
			{Name: "shard", Usage: "Shard URL for --mailbox"},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: message send <peer> <text...>")
			}
			via := ctx.Get("via")
			if via == "" && ctx.Session != nil {
				via = ctx.Session.Relay
			}
			identity, err := identityOrSession(ctx)
			if err != nil {
				return err
			}
			text := ""
			if len(ctx.Args) > 1 {
				text = joinWords(ctx.Args[1:])
			}
			return transportops.MessageSend(depsFor(ctx), transportops.MessageSendParams{
				TransportID: via, Identity: identity, Peer: ctx.Args[0],
				Text: text, TicketB64: ctx.Get("ticket"),
				MailboxID: ctx.Get("mailbox"), ShardURL: ctx.Get("shard"),
			})
		},
	})

	// ---- peer group ----
	submit("peer connect", &shellcmd.Command{
		Name: "connect", Short: "Create a handshake offer and send it through the active relay",
		ArgsUsage: "<peer>",
		Args:      []registry.ArgKind{registry.ArgPeer},
		Flags: []shellcmd.Flag{
			{Name: "id", Short: "i", Usage: "Local peer ID (defaults to session identity)"},
			{Name: "via", Usage: "Transport ID (defaults to session relay)"},
			{Name: "mailbox", Usage: "Explicit recipient mailbox, 32 hex (address-shared transports)"},
			{Name: "shard", Usage: "Shard URL for --mailbox"},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: peer connect <peer>")
			}
			via := ctx.Get("via")
			if via == "" && ctx.Session != nil {
				via = ctx.Session.Relay
			}
			identity, err := identityOrSession(ctx)
			if err != nil {
				return err
			}
			return transportops.PeerConnect(depsFor(ctx), transportops.PeerConnectParams{
				TransportID: via, Identity: identity, Peer: ctx.Args[0],
				MailboxID: ctx.Get("mailbox"), ShardURL: ctx.Get("shard"),
			})
		},
	})
	submit("peer address", &shellcmd.Command{
		Name: "address", Short: "Record a peer's explicit relay address (mailbox+shard)",
		ArgsUsage: "<peer>",
		Args:      []registry.ArgKind{registry.ArgPeer},
		Flags: []shellcmd.Flag{
			{Name: "mailbox", Usage: "Recipient mailbox, 32 hex", Required: true},
			{Name: "shard", Usage: "Shard URL", Required: true},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: peer address <peer> --mailbox <hex> --shard <url>")
			}
			return transportops.PeerRecord(depsFor(ctx), transportops.PeerRecordParams{
				Peer: ctx.Args[0], MailboxID: ctx.Get("mailbox"), ShardURL: ctx.Get("shard"),
			})
		},
	})
	submit("peer list", &shellcmd.Command{
		Name: "list", Short: "List every peer ID this session knows",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			peers := []string{}
			addrs := map[string]shellcmd.PeerAddr{}
			if ctx.Session != nil {
				peers = append([]string{}, ctx.Session.Peers...)
				addrs = ctx.Session.PeerMailboxes
			}
			if d.JSON {
				return d.JSONOut(map[string]any{"peers": peers})
			}
			if len(peers) == 0 {
				d.Human("No peers yet. `peer connect <id>` or poll to learn some.")
				return nil
			}
			for _, p := range peers {
				d.Human("  %s", p)
			}
			if len(addrs) > 0 {
				d.Human("Explicit addresses:")
				names := make([]string, 0, len(addrs))
				for _, a := range addrs {
					label := a.PeerID
					if label == "" {
						label = a.MailboxID
					}
					names = append(names, label+" @ "+a.ShardURL+" ("+a.MailboxID+")")
				}
				sort.Strings(names)
				for _, n := range names {
					d.Human("  %s", n)
				}
			}
			return nil
		},
	})

	// ---- identity group ----
	submit("identity init", &shellcmd.Command{
		Name: "init", Short: "Create a fresh identity and select it",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			return transportops.IdentityInit(depsFor(ctx))
		},
	})
	submit("identity load", &shellcmd.Command{
		Name: "load", Short: "Load an existing identity and select it",
		ArgsUsage: "<id>",
		Args:      []registry.ArgKind{registry.ArgIdentity},
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: identity load <id>")
			}
			return transportops.IdentityLoad(depsFor(ctx), ctx.Args[0])
		},
	})
	submit("identity list", &shellcmd.Command{
		Name: "list", Short: "List local identity profiles",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			return transportops.IdentityList(depsFor(ctx))
		},
	})
	submit("identity use", &shellcmd.Command{
		Name: "use", Short: "Select the active identity",
		ArgsUsage: "<id>",
		Args:      []registry.ArgKind{registry.ArgIdentity},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: identity use <id>")
			}
			return transportops.IdentityUse(depsFor(ctx), ctx.Args[0])
		},
	})
	submit("identity info", &shellcmd.Command{
		Name: "info", Short: "Show the active identity (never prints key material)",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			return transportops.IdentityInfo(depsFor(ctx))
		},
	})

	// ---- contact group ----
	submit("contact add", &shellcmd.Command{
		Name: "add", Short: "Map a friendly name to a peer ID",
		ArgsUsage: "<name> <userid>",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 2 {
				return fmt.Errorf("usage: contact add <name> <userid>")
			}
			return transportops.ContactAdd(depsFor(ctx), ctx.Args[0], ctx.Args[1])
		},
	})
	submit("contact remove", &shellcmd.Command{
		Name: "remove", Short: "Delete a contact",
		ArgsUsage: "<name>",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: contact remove <name>")
			}
			return transportops.ContactRemove(depsFor(ctx), ctx.Args[0])
		},
	})
	submit("contact list", &shellcmd.Command{
		Name: "list", Short: "List all contacts",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			return transportops.ContactList(depsFor(ctx))
		},
	})
	submit("contact info", &shellcmd.Command{
		Name: "info", Short: "Show one contact",
		ArgsUsage: "<name>",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: contact info <name>")
			}
			return transportops.ContactInfo(depsFor(ctx), ctx.Args[0])
		},
	})
	submit("contact note", &shellcmd.Command{
		Name: "note", Short: "Attach a free-text note (empty clears)",
		ArgsUsage: "<name> [text...]",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: contact note <name> [text...]")
			}
			note := ""
			if len(ctx.Args) > 1 {
				note = joinWords(ctx.Args[1:])
			}
			return transportops.ContactNote(depsFor(ctx), ctx.Args[0], note)
		},
	})
	submit("contact rename", &shellcmd.Command{
		Name: "rename", Short: "Rename a contact",
		ArgsUsage: "<old> <new>",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 2 {
				return fmt.Errorf("usage: contact rename <old> <new>")
			}
			return transportops.ContactRename(depsFor(ctx), ctx.Args[0], ctx.Args[1])
		},
	})

	// ---- mailbox ----
	submit("mailbox", &shellcmd.Command{
		Name: "mailbox", Short: "List conversation threads, or read one: mailbox [thread]",
		ArgsUsage: "[thread]",
		Args:      []registry.ArgKind{registry.ArgThread},
		Flags: []shellcmd.Flag{
			{Name: "id", Short: "i", Usage: "Local peer ID (defaults to session identity)"},
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			identity, err := identityOrSession(ctx)
			if err != nil {
				return err
			}
			if len(ctx.Args) == 0 {
				return transportops.MailboxList(depsFor(ctx), identity)
			}
			return transportops.MailboxRead(depsFor(ctx), identity, ctx.Args[0])
		},
	})

	// ---- session commands ----
	submit("use", &shellcmd.Command{
		Name: "use", Short: "Select session context: use identity <id> | use relay <id>",
		ArgsUsage: "<identity|relay> <id>",
		Long: "Pick once per session, then every command falls back to it.\n" +
			"Examples:\n" +
			"  use identity alice\n" +
			"  use relay filerelay",
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 2 {
				return fmt.Errorf("usage: use identity <id> | use relay <id>  (try `identity list` / `transport list`)")
			}
			switch ctx.Args[0] {
			case "identity":
				return transportops.IdentityUse(depsFor(ctx), ctx.Args[1])
			case "relay":
				if ctx.Session != nil {
					ctx.Session.Relay = ctx.Args[1]
				}
				d := depsFor(ctx)
				if d.JSON {
					return d.JSONOut(map[string]any{"relay": ctx.Args[1]})
				}
				d.Human("✓ Using relay %q. Next: `transport poll` or `peer connect <peer>`.", ctx.Args[1])
				return nil
			default:
				return fmt.Errorf("usage: use identity <id> | use relay <id>")
			}
		},
	})
	submit("quickstart", &shellcmd.Command{
		Name: "quickstart", Aliases: []string{"start", "guide", "tutorial"},
		Short: "Friendly 5-step tour: identity → relay → handshake → chat → files",
		Long: "The fastest way to learn the shell. Each step is copy-pasteable;\n" +
			"run `help <command>` for full flags on any step.",
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			if d.JSON {
				return d.JSONOut(map[string]any{"guide": []string{
					"identity init", "transport list", "use relay <id>",
					"peer connect <peer>", "message send <peer> hello",
				}})
			}
			steps := [][3]string{
				{"①", "Who are you?", "`identity init` creates you · `identity list` finds you again · `use identity <id>` selects you"},
				{"②", "Where do messages travel?", "`transport list` shows relays · `use relay <id>` selects one · `relay ping` checks it"},
				{"③", "Say hello securely", "`peer connect <peer>` sends the handshake · `transport poll` finishes it (both sides poll)"},
				{"④", "Chat", "`message send <peer> hello there` · `mailbox` reads threads · `mailbox <peer>` opens one"},
				{"⑤", "Share files", "`xfer send --to <peer> -f photo.bin` · paste the ticket into `message send` · receiver runs `xfer recv <ticket> -o out.bin`"},
			}
			d.Human("NexTalk in 5 steps (run `context` anytime to see where you are):")
			d.Human("")
			for _, s := range steps {
				d.Human("  %s  %s", s[0], s[1])
				d.Human("      %s", s[2])
			}
			d.Human("")
			d.Human("Tips: Tab completes everything · `help <command>` shows flags · history is never saved to disk.")
			return nil
		},
	})
	submit("context", &shellcmd.Command{
		Name: "context", Short: "Show session state: identity, relay, active transfers",
		Flags: []shellcmd.Flag{
			{Name: "json", Usage: "Machine-readable JSON on stdout", IsBool: true},
		},
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			id, relay := "-", "-"
			var transfers []shellcmd.TransferRef
			if ctx.Session != nil {
				if ctx.Session.Identity != "" {
					id = ctx.Session.Identity
				}
				if ctx.Session.Relay != "" {
					relay = ctx.Session.Relay
				}
				transfers = ctx.Session.Transfers
			}
			if transfers == nil {
				transfers = []shellcmd.TransferRef{}
			}
			if d.JSON {
				return d.JSONOut(map[string]any{
					"identity": id, "relay": relay, "transfers": transfers,
				})
			}
			if ctx.Session != nil {
				d.Human("%s", ctx.Session.StatusLine())
			} else {
				d.Human("Identity:")
				d.Human("  %s", id)
				d.Human("")
				d.Human("Relay:")
				d.Human("  %s", relay)
			}
			d.Human("")
			d.Human("Active transfers:")
			if len(transfers) == 0 {
				d.Human("  none — try `xfer send --to <peer> -f <file>`")
				return nil
			}
			for _, t := range transfers {
				d.Human("  %s  %s (%d bytes)", t.ID, t.File, t.Size)
			}
			return nil
		},
	})
	submit("alias", &shellcmd.Command{
		Name: "alias", Short: "Define or list aliases: alias [name [expansion]]",
		ArgsUsage: "[name [expansion...]]",
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			if ctx.Session == nil {
				return fmt.Errorf("no session")
			}
			if len(ctx.Args) == 0 {
				names := make([]string, 0, len(ctx.Session.Aliases))
				for n := range ctx.Session.Aliases {
					names = append(names, n)
				}
				sort.Strings(names)
				if d.JSON {
					return d.JSONOut(map[string]any{"aliases": ctx.Session.Aliases})
				}
				for _, n := range names {
					d.Human("  %s = %s", n, ctx.Session.Aliases[n])
				}
				return nil
			}
			if len(ctx.Args) == 1 {
				exp, ok := ctx.Session.Aliases[ctx.Args[0]]
				if !ok {
					return fmt.Errorf("no alias %q", ctx.Args[0])
				}
				if d.JSON {
					return d.JSONOut(map[string]any{"alias": ctx.Args[0], "expansion": exp})
				}
				d.Human("  %s = %s", ctx.Args[0], exp)
				return nil
			}
			ctx.Session.Aliases[ctx.Args[0]] = joinWords(ctx.Args[1:])
			if d.JSON {
				return d.JSONOut(map[string]any{"alias": ctx.Args[0], "expansion": ctx.Session.Aliases[ctx.Args[0]]})
			}
			d.Human("Alias %q set.", ctx.Args[0])
			return nil
		},
	})
	submit("set", &shellcmd.Command{
		Name: "set", Short: "Toggle session modes: set <json|show-secrets|transports-dir> <value>",
		ArgsUsage: "<key> <value>",
		Run: func(ctx *shellcmd.Context) error {
			if len(ctx.Args) < 1 {
				return fmt.Errorf("usage: set <json|show-secrets|transports-dir> <value>")
			}
			d := depsFor(ctx)
			if ctx.Session == nil {
				return fmt.Errorf("no session")
			}
			key := ctx.Args[0]
			val := ""
			if len(ctx.Args) > 1 {
				val = ctx.Args[1]
			}
			on := val == "on" || val == "true" || val == "1" || val == "yes"
			switch key {
			case "json":
				ctx.Session.JSON = on
			case "show-secrets":
				ctx.Session.ShowSecrets = on
			case "transports-dir":
				if val == "" {
					return fmt.Errorf("usage: set transports-dir <dir>")
				}
				ctx.Session.TransportsDir = val
			default:
				return fmt.Errorf("unknown setting %q (want json, show-secrets, transports-dir)", key)
			}
			if d.JSON {
				return d.JSONOut(map[string]any{"set": key, "value": val})
			}
			d.Human("Set %s = %s.", key, val)
			return nil
		},
	})
	submit("history", &shellcmd.Command{
		Name: "history", Short: "Show this session's command history (in-memory only, never saved)",
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			hist := []string{}
			if ctx.Session != nil {
				hist = ctx.Session.History
			}
			if d.JSON {
				return d.JSONOut(map[string]any{"history": hist})
			}
			for i, line := range hist {
				d.Human("  %4d  %s", i+1, line)
			}
			return nil
		},
	})
	submit("clear", &shellcmd.Command{
		Name: "clear", Short: "Clear the screen",
		Run: func(ctx *shellcmd.Context) error {
			ui.ClearScreen()
			return nil
		},
	})
	submit("version", &shellcmd.Command{
		Name: "version", Short: "Print the nextalk build version",
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			if d.JSON {
				return d.JSONOut(map[string]any{"version": buildinfo.String()})
			}
			d.Human("%s", buildinfo.String())
			return nil
		},
	})
	submit("help", &shellcmd.Command{
		Name: "help", Short: "Show help: help [command...]",
		ArgsUsage: "[command...]",
		Run: func(ctx *shellcmd.Context) error {
			d := depsFor(ctx)
			if len(ctx.Args) == 0 {
				printTopHelp(d)
				return nil
			}
			cmd, _, path := r.Resolve(ctx.Args)
			if cmd == nil {
				if sug := shellcmd.Suggest(r, strings.Join(ctx.Args, " ")); len(sug) > 0 {
					return fmt.Errorf("unknown command %q; did you mean: %s?",
						strings.Join(ctx.Args, " "), strings.Join(sug, ", "))
				}
				return fmt.Errorf("unknown command %q", strings.Join(ctx.Args, " "))
			}
			d.Human("%s", shellcmd.HelpText(path, cmd))
			return nil
		},
	})
	submit("exit", &shellcmd.Command{
		Name: "exit", Aliases: []string{"quit"},
		Short: "Leave the shell",
		Run: func(ctx *shellcmd.Context) error {
			return errExitShell
		},
	})
	return r
}

// printTopHelp lists every command group with one-line summaries,
// grouped by workflow so beginners see the happy path first.
func printTopHelp(d *transportops.Deps) {
	type item struct {
		name, short, icon string
	}
	sections := []struct {
		title string
		items []item
	}{
		{"🚀 Start here", []item{
			{"quickstart", "5-step tour: identity → relay → chat → files", "✨"},
			{"identity", "Identities (init/load/list/use/info)", "👤"},
			{"use", "Select session context (identity/relay)", "🎯"},
			{"context", "Show session state", "📍"},
		}},
		{"💬 Messaging", []item{
			{"peer", "Handshake and peer discovery (connect/list)", "🤝"},
			{"message", "Send E2E messages through the active relay", "💬"},
			{"mailbox", "Read conversation history", "📥"},
			{"contact", "Address book (add/remove/list/info/note/rename)", "📇"},
		}},
		{"📦 Transports & files", []item{
			{"transport", "Manage runtime transport modules (list/install/poll/...)", "🔌"},
			{"relay", "Message-relay diagnostics (list/ping/info)", "📡"},
			{"xfer", "End-to-end file transfers (send/recv/resume/cancel/inspect)", "📁"},
		}},
		{"🛠 Shell", []item{
			{"alias", "Define or list aliases", "🏷"},
			{"set", "Toggle session modes (json/show-secrets/transports-dir)", "⚙"},
			{"history", "Show session command history", "🕘"},
			{"switch", "Enter a legacy transport sub-shell", "🔀"},
			{"help", "Show help", "❓"},
			{"clear", "Clear the screen", "🧹"},
			{"exit", "Leave the shell", "👋"},
		}},
	}
	d.Human("NexTalk shell — every operation lives here. `help <command>` for details, `quickstart` for the tour.")
	d.Human("")
	for _, sec := range sections {
		d.Human("%s", sec.title)
		for _, g := range sec.items {
			d.Human("  %s  %-10s %s", g.icon, g.name, g.short)
		}
		d.Human("")
	}
	d.Human("Session: `use identity <id>`, `use relay <id>`; `context` shows state. Tab completes everything.")
}

func joinWords(words []string) string {
	out := ""
	for i, w := range words {
		if i > 0 {
			out += " "
		}
		out += w
	}
	return out
}
