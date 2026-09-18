package transportops

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	Client "github.com/erfanheydarzade/NexTalk/client"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	ntx "github.com/erfanheydarzade/NexTalk/internal/transport"
)

// ─── Identity registration (the real per-pubkey mailbox) ────────────────────
//
// Why this exists: the Router derives a mailbox address purely from a public
// key — mailbox_id = HMAC_SHA256(pubkey, SERVER_SECRET), identical code in
// both router.js handleRegister and handleResolve. A mailbox therefore only
// exists at HMAC(P) if someone called POST /register while proving ownership
// of P (verifyEd25519 over "register:<pubkey>:<timestamp>").
//
// The nextalk-relay bridge cannot do that: by design it never sees user
// private keys, so its onRegister signs with a per-tag *scoped* key and
// creates a mailbox at HMAC(scoped_pub). Meanwhile every send/resolve path
// addresses peers by their NexTalk identity pubkey, i.e. HMAC(identity_pub) —
// an address nobody ever registered. handleResolve never 404s (it falls
// through to a current-era guess carrying a "note"), so the failure only
// surfaces later as the shard's 404 "Mailbox not found or expired".
//
// IdentityRegister closes that gap from core, where the identity private key
// actually lives — mirroring what cmd/worker/register.go has always done —
// and then teaches the bridge about the resulting mailbox so receiving works
// too:
//
//  1. POST /register with the identity key   → mailbox created at HMAC(id_pub)
//  2. bridge XferResolve(own pubkey)         → records alias → full-ID binding
//     in mailbox-map.json and hands back the
//     16-byte transport alias
//  3. AttachMailbox(alias, read_secret, ...) → the mailbox becomes pollable
//
// Step 2 is what makes step 3 possible at all: the bridge's expandAlias only
// knows bindings it recorded itself during register/resolve, and the Router's
// 32-byte mailbox_id does not fit the transport API's 16-byte mailbox field.

// IdentityRegistration is the machine-readable result of IdentityRegister.
type IdentityRegistration struct {
	Identity   string `json:"identity"`
	Pubkey     string `json:"pubkey"`
	MailboxID  string `json:"mailbox_id"`  // full 32-byte relay mailbox id
	Alias      string `json:"alias"`       // 16-byte transport alias
	ReadSecret string `json:"read_secret"` // redacted in human output
	ShardURL   string `json:"shard_url"`
	RouterURL  string `json:"router_url"`
	Attached   bool   `json:"attached"`
}

// IdentityRegister registers the active identity's real pubkey with the
// Router and attaches the resulting mailbox to the transport.
//
// Safe to re-run: RouterClient.Register is cached per-pubkey until the
// capability expires, /register is idempotent for a given pubkey (the
// mailbox_id is a pure function of it), and AddAttachment upserts — so
// re-running refreshes a rotated read_secret without creating anything new.
//
// router may be empty when the URL is available from `transport config
// <id> {"router_url":"..."}` or from a previous attachment.
func IdentityRegister(d *Deps, transportID, identity, router string) (*IdentityRegistration, error) {
	if strings.TrimSpace(identity) == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if strings.TrimSpace(identity) == "" {
		return nil, fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}

	cl, err := Client.LoadClient(identity)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if len(cl.IdentityPrivate) == 0 || len(cl.IdentityPublic) != 32 {
		return nil, fmt.Errorf("identity %s has no usable ed25519 identity key", shortHex(identity))
	}
	pubHex := hex.EncodeToString(cl.IdentityPublic)

	m, err := d.Manager()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(router) == "" {
		router = routerURLFor(m, transportID)
	}
	if strings.TrimSpace(router) == "" {
		return nil, fmt.Errorf("no router_url: pass --router or run `transport config %s '{\"router_url\":\"https://...\"}'`", transportID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ── 1. Register the identity pubkey itself with the Router ──────────
	rc := workerrelay.NewRouterClient(router)
	cap, err := rc.Register(ctx, cl.IdentityPrivate)
	if err != nil {
		return nil, fmt.Errorf("router /register for %s: %w", shortHex(pubHex), err)
	}
	if cap.MailboxID == "" || cap.ReadSecret == "" || cap.ShardURL == "" {
		return nil, fmt.Errorf("router /register returned an incomplete capability")
	}
	secret, err := hex.DecodeString(cap.ReadSecret)
	if err != nil || len(secret) != 32 {
		return nil, fmt.Errorf("router /register returned a malformed read_secret")
	}

	out := &IdentityRegistration{
		Identity:   identity,
		Pubkey:     pubHex,
		MailboxID:  cap.MailboxID,
		ReadSecret: cap.ReadSecret,
		ShardURL:   cap.ShardURL,
		RouterURL:  router,
	}

	// ── 2 & 3. Teach the transport the mailbox, then attach it ──────────
	//
	// Best-effort: the mailbox now exists server-side, so peers can already
	// send to this identity even if the local transport is down. Only
	// *receiving* needs the attach, so a failure here is reported as a
	// warning rather than unwinding a successful registration.
	tr, err := m.EnsureRunning(ctx, transportID)
	if err != nil {
		d.Human("[!] Registered, but transport %s is not running (%v).", transportID, err)
		d.Human("    Run `transport register-identity` again once it starts to attach for receiving.")
		return out, nil
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		d.Human("[!] Registered, but %s cannot resolve mailbox aliases (%v).", transportID, err)
		return out, nil
	}

	// Resolving our own pubkey is what makes the transport record the
	// alias → full-mailbox-id binding it needs to expand the alias later.
	alias, shard, err := ft.XferResolve(ctx, cl.IdentityPublic, router)
	if err != nil {
		d.Human("[!] Registered, but resolving own mailbox through %s failed: %v", transportID, err)
		return out, nil
	}
	if shard == "" {
		shard = cap.ShardURL
	}
	out.Alias = hex.EncodeToString(alias)

	if err := tr.AttachMailbox(ctx, alias, secret, shard, router); err != nil {
		d.Human("[!] Registered, but attach failed: %v", err)
		return out, nil
	}
	_ = m.AddAttachment(transportID, ntx.Attachment{
		MailboxID:  out.Alias,
		ReadSecret: cap.ReadSecret,
		ShardURL:   shard,
		RouterURL:  router,
		Owner:      identity,
	})
	out.Attached = true
	out.ShardURL = shard

	if d.JSON {
		return out, d.JSONOut(out)
	}
	d.Human("✓ Identity %s registered with the Router.", shortHex(identity))
	d.Human("")
	d.Human("pubkey:     %s", pubHex)
	d.Human("mailbox:    %s", out.MailboxID)
	d.Human("alias:      %s", out.Alias)
	d.Human("read_secret:%s", d.Secret(cap.ReadSecret))
	d.Human("shard:      %s", shard)
	d.Human("")
	d.Human("[i] Peers can now reach you by pubkey. Next: `peer connect <peer>`.")
	return out, nil
}

// routerURLFor recovers a router URL from stored transport config, then from
// any prior attachment. Shared by IdentityRegister and FilerelayRegister so
// the two cannot drift.
func routerURLFor(m *ntx.Manager, transportID string) string {
	if m == nil {
		return ""
	}
	if cfg := m.Config(transportID); cfg != "" {
		var obj map[string]string
		if json.Unmarshal([]byte(cfg), &obj) == nil && obj["router_url"] != "" {
			return obj["router_url"]
		}
	}
	for _, a := range m.Attachments(transportID) {
		if a.RouterURL != "" {
			return a.RouterURL
		}
	}
	return ""
}