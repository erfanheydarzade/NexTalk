package transportops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	ntx "github.com/erfanheydarzade/NexTalk/internal/transport"
)

// resolveRecipient accepts a NexTalk peer ID or a 64-char hex Ed25519 pubkey.
func resolveRecipient(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if raw, err := hex.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	pub, err := relay.PeerIDToEd25519Pub(s)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient %q: peer ID or 64-hex pubkey required", s)
	}
	return pub, nil
}

func shortHex(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-4:]
}

// printDispatchEvent renders one dispatch event (human UI).
func printDispatchEvent(d *Deps, e dispatch.Event) {
	switch e.Type {
	case "offer":
		d.Human("[+] Offer received from %s (answer sent)", e.Peer)
	case "answer":
		d.Human("[+] Session established with %s", e.Peer)
	case "message":
		d.Human("[+] Message from %s (%s) — stored in mailbox:\n%s", e.Sender, e.Encoding, e.Message)
	case "group_message":
		d.Human("[+] Group message in [%s] from %s — stored in mailbox:\n%s",
			e.Context, e.Sender, e.Message)
	case "error":
		d.Human("[✗] %s", e.Message)
	default:
		d.Human("[?] Unknown event: %s", e.Type)
	}
}

// AttachParams subscribes a mailbox for polling.
type AttachParams struct {
	TransportID string
	MailboxID   string // 32 lowercase hex (16B)
	ReadSecret  string // 64 hex (32B bearer); "" + shell prompt when interactive
	ShardURL    string
	RouterURL   string
}

// Attach subscribes a mailbox. The secret is a bearer, never a key; when it
// is absent and the shell can prompt, hidden input is used instead of flags.
func Attach(d *Deps, p AttachParams) error {
	secret, err := d.SecretOr(p.ReadSecret, "read secret (hidden): ")
	if err != nil {
		return err
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	owner := ""
	if d.Session != nil {
		owner = d.Session.Identity
	}
	if err := m.AddAttachment(p.TransportID, ntx.Attachment{
		MailboxID:  p.MailboxID,
		ReadSecret: secret,
		ShardURL:   p.ShardURL,
		RouterURL:  p.RouterURL,
		Owner:      owner,
	}); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"attached": shortHex(p.MailboxID), "transport": p.TransportID})
	}
	d.Human("Attached mailbox %s.", shortHex(p.MailboxID))
	return nil
}

// Detach unsubscribes a mailbox after confirmation.
func Detach(d *Deps, transportID, mailboxID string) error {
	ok, err := d.ConfirmOr(fmt.Sprintf("Detach mailbox %s from %q?", shortHex(mailboxID), transportID))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted")
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	if err := m.RemoveAttachment(transportID, mailboxID); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"detached": shortHex(mailboxID), "transport": transportID})
	}
	d.Human("Detached mailbox %s.", shortHex(mailboxID))
	return nil
}

// PollParams selects what to poll and how to report it.
type PollParams struct {
	TransportID string
	Identity    string // local peer ID; "" falls back to the session identity
	Mailbox     string // optional single mailbox filter (hex)
	Limit       int
	Format      string // "human" or "json"
}

// Poll fetches frames from a transport and dispatches them through the
// shared core path (decrypt + mailbox, same as worker listen).
func Poll(d *Deps, p PollParams) error {
	if p.Format != "" && p.Format != "human" && p.Format != "json" {
		return fmt.Errorf("invalid format %q (want human or json)", p.Format)
	}
	asJSON := d.JSON || p.Format == "json"
	identity := p.Identity
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, p.TransportID)
	if err != nil {
		return err
	}
	cl, err := Client.LoadClient(identity)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	atts := m.Attachments(p.TransportID)
	if p.Mailbox != "" {
		found := false
		for _, a := range atts {
			if a.MailboxID == p.Mailbox {
				atts = []ntx.Attachment{a}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("mailbox %s not attached (see `transport attach`)", p.Mailbox)
		}
	} else if identity != "" {
		// When sharing one transports dir between two peers, each register
		// auto-attaches with Owner = peer ID. Polling as peer A must not
		// drain peer B's mailbox (burn-after-read would lose mail).
		hasOwner := false
		for _, a := range atts {
			if a.Owner != "" {
				hasOwner = true
				break
			}
		}
		if hasOwner {
			var filtered []ntx.Attachment
			for _, a := range atts {
				if a.Owner == "" || a.Owner == identity {
					filtered = append(filtered, a)
				}
			}
			if len(filtered) > 0 {
				atts = filtered
			}
		}
	}
	if len(atts) == 0 {
		return fmt.Errorf("no mailboxes attached (see `transport attach` or `transport register`)")
	}
	limit := p.Limit
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	deps := dispatch.OpenDeps(cl)
	sender := func(ctx context.Context, recipientPub []byte, t relay.Type, payload []byte) error {
		hint := ntx.RouteHint{RecipientPub: recipientPub, SenderHint: cl.IdentityPublic}
		// Auto-replies (handshake answers) target the peer's explicit
		// address when `peer address` recorded one — address-shared
		// relays cannot route the reply by pubkey.
		if addr, ok := peerAddrFor(d, recipientPub); ok {
			mbox, _ := hex.DecodeString(addr.MailboxID)
			hint = ntx.RouteHint{MailboxID: mbox, ShardURL: addr.ShardURL, SenderHint: cl.IdentityPublic}
		}
		return tr.SendFrame(ctx, ntx.WrapFrame(t, payload), hint)
	}
	var events []dispatch.Event
	for _, a := range atts {
		mid, _ := hex.DecodeString(a.MailboxID)
		sec, _ := hex.DecodeString(a.ReadSecret)
		if err := tr.AttachMailbox(ctx, mid, sec, a.ShardURL, a.RouterURL); err != nil {
			events = append(events, dispatch.Event{Type: "error", Message: fmt.Sprintf("attach %s: %v", shortHex(a.MailboxID), err)})
			continue
		}
		frames, err := tr.PollFrames(ctx, limit, mid)
		if err != nil {
			events = append(events, dispatch.Event{Type: "error", Message: err.Error()})
			continue
		}
		events = append(events, dispatch.DispatchBatch(ctx, cl, cl.IdentityPrivate, frames, deps, sender)...)
	}
	// Persist any session progress the dispatch made.
	Client.SaveClient(cl)
	if d.Session != nil {
		for _, e := range events {
			// Learn every peer we hear from so Tab completes them next time.
			d.Session.RememberPeer(e.Sender)
			d.Session.RememberPeer(e.Peer)
		}
	}
	if asJSON {
		return d.JSONOut(map[string]any{"events": events})
	}
	if len(events) == 0 {
		d.Human("[i] No new events.")
		return nil
	}
	for _, e := range events {
		printDispatchEvent(d, e)
	}
	return nil
}

// SendFrameParams delivers one already-encrypted frame file.
type SendFrameParams struct {
	TransportID string
	Peer        string // peer ID or 64-hex pubkey; "" with MailboxID
	MailboxID   string // 32 hex explicit recipient mailbox
	ShardURL    string // required with MailboxID
	File        string
}

// SendFrame delivers one already-encrypted frame file to a peer.
func SendFrame(d *Deps, p SendFrameParams) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(p.File)
	if err != nil {
		return fmt.Errorf("read frame: %w", err)
	}
	if len(raw) < 2 || len(raw) > 40*1024 {
		return fmt.Errorf("frame out of bounds (%d bytes)", len(raw))
	}
	hint := ntx.RouteHint{}
	if p.MailboxID != "" {
		mbox, err := hex.DecodeString(p.MailboxID)
		if err != nil || len(mbox) != 16 {
			return fmt.Errorf("mailbox must be 32 hex chars")
		}
		if p.ShardURL == "" {
			return fmt.Errorf("--shard is required with --mailbox")
		}
		hint.MailboxID = mbox
		hint.ShardURL = p.ShardURL
	} else {
		pub, err := resolveRecipient(p.Peer)
		if err != nil {
			return err
		}
		hint.RecipientPub = pub
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, p.TransportID)
	if err != nil {
		return err
	}
	if err := tr.SendFrame(ctx, raw, hint); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"delivered": true, "bytes": len(raw)})
	}
	d.Human("Frame delivered.")
	return nil
}

// deriveUserTag returns a deterministic scoped-credential tag from a NexTalk
// peer ID (hex(pubkey) is 64 chars, peer ID is ~100 chars). The bridge
// requires ^[a-z0-9][a-z0-9-]{0,63}$ and treats distinct tags as distinct
// mailboxes, so two peers sharing one transports dir get two mailboxes without
// manually picking "alice"/"bob".
func deriveUserTag(peerID string) string {
	if peerID == "" {
		return ""
	}
	// 16 hex chars of SHA256(peerID) -> always lowercase hex, fits tagRe.
	h := sha256.Sum256([]byte(peerID))
	return hex.EncodeToString(h[:8])
}

// FilerelayRegister mints a FILE-TRANSFER mailbox via the transport's scoped
// credential. It is NOT identity registration: the mailbox it creates lives
// at HMAC(scoped_pubkey), not at HMAC(identity_pubkey), so peers addressing
// this identity by pubkey will never reach it. Use IdentityRegister for
// messaging setup; this is the `xfer register` path. The mailbox tag is always derived from the peer ID —
// deterministic and collision-free when multiple peers share one transports
// dir. Pass identity explicitly (-i/--id) or have it set via `use identity`.
// The read_secret bearer is redacted in human output; --json carries the real
// value. --router is optional when stored via `transport config <id> {"router_url":"..."}` or a prior attach.
// On success the mailbox is auto-attached (upsert) so `transport attach` is
// never required; re-register refreshes the stored bearer on relay rotation.
func FilerelayRegister(d *Deps, transportID, identity, router string) error {
	if strings.TrimSpace(identity) == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if strings.TrimSpace(identity) == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	user := deriveUserTag(identity)
	if strings.TrimSpace(router) == "" {
		// Fall back to stored config or prior attach's router_url so
		// `xfer register <id>` works after `transport config <id> ...`.
		if m0, err := d.Manager(); err == nil {
			router = routerURLFor(m0, transportID)
		}
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, transportID)
	if err != nil {
		return err
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		return err
	}
	mbox, sec, shard, rurl, err := ft.XferRegister(ctx, user, router)
	if err != nil {
		return err
	}
	// Auto-attach (upsert): makes the mailbox immediately pollable and
	// survives restarts / secret rotation without manual `attach`.
	owner := ""
	if d.Session != nil {
		owner = d.Session.Identity
	}
	_ = m.AddAttachment(transportID, ntx.Attachment{
		MailboxID:  hex.EncodeToString(mbox),
		ReadSecret: hex.EncodeToString(sec),
		ShardURL:   shard,
		RouterURL:  rurl,
		Owner:      owner,
	})
	if d.JSON {
		return d.JSONOut(map[string]any{
			"mailbox_id":  hex.EncodeToString(mbox),
			"read_secret": hex.EncodeToString(sec),
			"shard_url":   shard,
			"router_url":  rurl,
			"attached":    true,
		})
	}
	d.Human("Mailbox %s minted and attached.", shortHex(hex.EncodeToString(mbox)))
	d.Human("read_secret: %s", d.Secret(hex.EncodeToString(sec)))
	d.Human("shard: %s", shard)
	return nil
}

// FilerelayResolve maps a recipient to mailbox + shard.
func FilerelayResolve(d *Deps, transportID, peer, router string) error {
	pub, err := resolveRecipient(peer)
	if err != nil {
		return err
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, transportID)
	if err != nil {
		return err
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		return err
	}
	mbox, shard, err := ft.XferResolve(ctx, pub, router)
	if err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{
			"mailbox_id": hex.EncodeToString(mbox),
			"shard_url":  shard,
		})
	}
	d.Human("mailbox: %s", shortHex(hex.EncodeToString(mbox)))
	d.Human("shard: %s", shard)
	return nil
}
