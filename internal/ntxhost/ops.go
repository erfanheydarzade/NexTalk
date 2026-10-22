package ntxhost

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// AttachParams subscribes a mailbox. ReadSecret is a per-mailbox bearer,
// never an identity key.
type AttachParams struct {
	Mailbox string // 32 hex
	Secret  string // 64 hex
	Shard   string
	Router  string
}

// Attach starts the transport if needed, subscribes the mailbox on it and
// records the attachment (upsert) owned by the active identity.
func (h *Host) Attach(ctx context.Context, id string, p AttachParams) error {
	att := transport.Attachment{MailboxID: strings.ToLower(p.Mailbox), ReadSecret: strings.ToLower(p.Secret), ShardURL: p.Shard, RouterURL: p.Router}
	mbox, sec, err := decodeAttachment(att)
	if err != nil {
		return fmt.Errorf("ntxhost: attach: %w", err)
	}
	if att.ShardURL == "" {
		return fmt.Errorf("ntxhost: attach: shard_url required")
	}
	ident, err := h.identity()
	if err != nil {
		return err
	}
	att.Owner = ident.Client.Id
	tr, _, err := h.ensure(ctx, id)
	if err != nil {
		return err
	}
	if err := tr.AttachMailbox(ctx, mbox, sec, att.ShardURL, att.RouterURL); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, ok := h.recs[id]
	if !ok {
		return fmt.Errorf("ntxhost: %q was removed", id)
	}
	for i, e := range rec.attach {
		if e.MailboxID == att.MailboxID {
			rec.attach[i] = att
			return nil
		}
	}
	rec.attach = append(rec.attach, att)
	return nil
}

// Detach unsubscribes a mailbox. It never starts a stopped transport.
func (h *Host) Detach(ctx context.Context, id, mailbox string) error {
	mailbox = strings.ToLower(mailbox)
	if len(mailbox) != 32 || !isHex(mailbox) {
		return fmt.Errorf("ntxhost: detach: mailbox must be 32 hex chars")
	}
	h.mu.Lock()
	rec, ok := h.recs[id]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("ntxhost: %q is not installed", id)
	}
	kept := rec.attach[:0:0]
	found := false
	for _, a := range rec.attach {
		if a.MailboxID == mailbox {
			found = true
			continue
		}
		kept = append(kept, a)
	}
	if !found {
		h.mu.Unlock()
		return fmt.Errorf("ntxhost: detach: mailbox not attached")
	}
	rec.attach = kept
	live := rec.live
	h.mu.Unlock()
	if live != nil {
		mb, _ := hex.DecodeString(mailbox)
		return live.DetachMailbox(ctx, mb)
	}
	return nil
}

func (h *Host) routerFor(id, router string) string {
	if strings.TrimSpace(router) != "" {
		return strings.TrimSpace(router)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if rec, ok := h.recs[id]; ok {
		for _, a := range rec.attach {
			if a.RouterURL != "" {
				return a.RouterURL
			}
		}
	}
	return ""
}

// Registration is the result of Register. ReadSecret is a bearer: treat the
// whole object as secret.
type Registration struct {
	MailboxID  string `json:"mailbox_id"`
	ReadSecret string `json:"read_secret"`
	ShardURL   string `json:"shard_url"`
	RouterURL  string `json:"router_url"`
}

// Register proves ownership of the active identity to the Router (the
// private key stays in core and signs locally, as cmd/worker does), then
// attaches the returned mailbox to the transport. WASM ABI v1 has no
// register op, so the Router exchange is done by core, not by the module.
func (h *Host) Register(ctx context.Context, id, router string) (*Registration, error) {
	ident, err := h.identity()
	if err != nil {
		return nil, err
	}
	if _, _, err := h.ensure(ctx, id); err != nil { // fail early, before touching the Router
		return nil, err
	}
	router = h.routerFor(id, router)
	if router == "" {
		return nil, fmt.Errorf("ntxhost: no router URL: pass { router }")
	}
	cap, err := h.registrar.Register(ctx, router, ident.Client.IdentityPrivate)
	if err != nil {
		return nil, fmt.Errorf("router /register: %w", err)
	}
	if len(cap.MailboxID) != 32 || !isHex(cap.MailboxID) || cap.ReadSecret == "" || cap.ShardURL == "" {
		return nil, fmt.Errorf("router /register returned an incomplete or unsupported capability")
	}
	out := &Registration{MailboxID: strings.ToLower(cap.MailboxID), ReadSecret: strings.ToLower(cap.ReadSecret), ShardURL: cap.ShardURL, RouterURL: router}
	if err := h.Attach(ctx, id, AttachParams{Mailbox: out.MailboxID, Secret: out.ReadSecret, Shard: out.ShardURL, Router: router}); err != nil {
		return nil, fmt.Errorf("registered, but attach failed: %w", err)
	}
	return out, nil
}

// ResolveRecipient accepts a NexTalk peer ID or a 64-hex Ed25519 pubkey.
func ResolveRecipient(s string) ([]byte, error) {
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

// Resolve maps a recipient to its mailbox + shard. A transport that
// implements XferResolve answers itself; otherwise the Router does.
func (h *Host) Resolve(ctx context.Context, id, to, router string) (mailbox, shard string, err error) {
	pub, err := ResolveRecipient(to)
	if err != nil {
		return "", "", err
	}
	tr, _, err := h.ensure(ctx, id)
	if err != nil {
		return "", "", err
	}
	router = h.routerFor(id, router)
	if router == "" {
		return "", "", fmt.Errorf("ntxhost: no router URL: pass { router }")
	}
	if r, ok := tr.(interface {
		XferResolve(ctx context.Context, recipientPub []byte, routerURL string) ([]byte, string, error)
	}); ok {
		mb, sh, err := r.XferResolve(ctx, pub, router)
		if err != nil {
			return "", "", err
		}
		return hex.EncodeToString(mb), sh, nil
	}
	res, err := h.registrar.Resolve(ctx, router, hex.EncodeToString(pub))
	if err != nil {
		return "", "", fmt.Errorf("router /resolve: %w", err)
	}
	return strings.ToLower(res.MailboxID), res.ShardURL, nil
}

// PollParams selects mailboxes. Limit is clamped to 1..32.
type PollParams struct {
	Mailbox string
	Limit   int
}

// Poll drains frames from the transport and runs them through
// internal/dispatch — the same receive path as `worker listen` and
// NexTalk.relay.listen() — so events and dedupe are identical.
func (h *Host) Poll(ctx context.Context, id string, p PollParams) ([]dispatch.Event, error) {
	ident, err := h.identity()
	if err != nil {
		return nil, err
	}
	tr, _, err := h.ensure(ctx, id)
	if err != nil {
		return nil, err
	}
	cl := ident.Client

	h.mu.Lock()
	var atts []transport.Attachment
	if rec, ok := h.recs[id]; ok {
		atts = append(atts, rec.attach...)
	}
	h.mu.Unlock()

	if p.Mailbox != "" {
		want := strings.ToLower(p.Mailbox)
		var pick []transport.Attachment
		for _, a := range atts {
			if a.MailboxID == want {
				pick = append(pick, a)
			}
		}
		if len(pick) == 0 {
			return nil, fmt.Errorf("ntxhost: mailbox %s is not attached", short(want))
		}
		atts = pick
	} else {
		// Never drain another identity's mailbox (burn-after-read would lose mail).
		var mine []transport.Attachment
		for _, a := range atts {
			if a.Owner == "" || a.Owner == cl.Id {
				mine = append(mine, a)
			}
		}
		atts = mine
	}
	if len(atts) == 0 {
		return nil, fmt.Errorf("ntxhost: no mailboxes attached for this identity (register or attach first)")
	}
	limit := p.Limit
	if limit <= 0 || limit > 32 {
		limit = 32
	}

	sender := func(ctx context.Context, recipientPub []byte, t relay.Type, payload []byte) error {
		return tr.SendFrame(ctx, relay.WrapEnvelope(t, payload), transport.RouteHint{RecipientPub: recipientPub, SenderHint: cl.IdentityPublic})
	}

	events := []dispatch.Event{}
	for _, a := range atts {
		mid, sec, err := decodeAttachment(a)
		if err != nil {
			events = append(events, dispatch.Event{Type: "error", Message: err.Error()})
			continue
		}
		if err := tr.AttachMailbox(ctx, mid, sec, a.ShardURL, a.RouterURL); err != nil {
			events = append(events, dispatch.Event{Type: "error", Message: fmt.Sprintf("attach %s: %v", short(a.MailboxID), err)})
			continue
		}
		frames, err := tr.PollFrames(ctx, limit, mid)
		if err != nil {
			events = append(events, dispatch.Event{Type: "error", Message: err.Error()})
			continue
		}
		if ident.Lock != nil {
			ident.Lock.Lock()
		}
		evs := dispatch.DispatchBatch(ctx, cl, cl.IdentityPrivate, frames, ident.Deps, sender)
		if ident.Lock != nil {
			ident.Lock.Unlock()
		}
		events = append(events, evs...)
	}
	return events, nil
}

// SendOptions overrides routing: Mailbox+Shard address a mailbox directly
// (needed by address-shared relays); otherwise the frame is routed by the
// recipient's public key.
type SendOptions struct {
	Mailbox string
	Shard   string
}

func routeHint(peer string, selfPub []byte, o SendOptions) (transport.RouteHint, error) {
	hint := transport.RouteHint{SenderHint: selfPub}
	if o.Mailbox != "" {
		mb, err := hex.DecodeString(strings.ToLower(o.Mailbox))
		if err != nil || len(mb) != 16 {
			return hint, fmt.Errorf("mailbox must be 32 hex chars")
		}
		if o.Shard == "" {
			return hint, fmt.Errorf("shard is required with mailbox")
		}
		hint.MailboxID, hint.ShardURL = mb, o.Shard
		return hint, nil
	}
	pub, err := ResolveRecipient(peer)
	if err != nil {
		return hint, err
	}
	hint.RecipientPub = pub
	return hint, nil
}

// SendMessage encrypts msg over the existing session with peer, wraps it as
// a layer-1 message frame and hands it to the transport.
func (h *Host) SendMessage(ctx context.Context, id, peer string, msg []byte, o SendOptions) error {
	ident, err := h.identity()
	if err != nil {
		return err
	}
	tr, pkg, err := h.ensure(ctx, id)
	if err != nil {
		return err
	}
	if !pkg.Manifest.HasCapability("message") {
		return fmt.Errorf("ntxhost: %q does not declare the \"message\" capability", id)
	}
	hint, err := routeHint(peer, ident.Client.IdentityPublic, o)
	if err != nil {
		return err
	}
	if ident.Lock != nil {
		ident.Lock.Lock()
	}
	ct, err := ident.Client.Encrypt(peer, msg)
	if ident.Lock != nil {
		ident.Lock.Unlock()
	}
	if err != nil {
		return err
	}
	frame := relay.WrapEnvelope(relay.TypeMessage, ct)
	if len(frame) > transport.MaxFrameBytes {
		return fmt.Errorf("ntxhost: message too large for one frame (%d > %d bytes)", len(frame), transport.MaxFrameBytes)
	}
	return tr.SendFrame(ctx, frame, hint)
}
