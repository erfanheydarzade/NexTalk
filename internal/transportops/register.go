package transportops

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/binary"
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
	MailboxID  string `json:"mailbox_id"`  // router mailbox identifier
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
	// Worker Relay and FileRelay deliberately have different wire protocols.
	// Keep the Worker Relay client intact, but use the FileRelay transport RPC
	// when the selected transport is FileRelay. The private key never leaves
	// NexTalk core; FileRelay receives only the signed registration proof.
	var mailboxIDDisplay string
	var mailboxID, secret []byte
	var shard, outRouter string
	var readSecret string

	if transportID == "filerelay" {
		tr, err := m.EnsureRunning(ctx, transportID)
		if err != nil {
			return nil, fmt.Errorf("start filerelay transport: %w", err)
		}
		ir, ok := tr.(interface {
			IdentityRegister(ctx context.Context, pubkey []byte, timestamp uint64, nonce, signature []byte, routerURL string) (mailboxID, readSecret []byte, shardURL, outRouter string, err error)
		})
		if !ok {
			return nil, fmt.Errorf("filerelay transport does not support identity registration; install the updated filerelay .ntx")
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, fmt.Errorf("generate register nonce: %w", err)
		}
		ts := uint64(time.Now().UnixMilli())
		sig := ed25519.Sign(cl.IdentityPrivate, canonicalFileRelayRegister(cl.IdentityPublic, ts, nonce))
		mailboxID, secret, shard, outRouter, err = ir.IdentityRegister(ctx, cl.IdentityPublic, ts, nonce[:], sig, router)
		if err != nil {
			return nil, fmt.Errorf("filerelay /register for %s: %w", shortHex(pubHex), err)
		}
		if len(mailboxID) != 16 || len(secret) != 32 || shard == "" {
			return nil, fmt.Errorf("filerelay /register returned an incomplete capability")
		}
		readSecret = hex.EncodeToString(secret)
		mailboxIDDisplay = hex.EncodeToString(mailboxID)
	} else {
		rc := workerrelay.NewRouterClient(router)
		cap, err := rc.Register(ctx, cl.IdentityPrivate)
		if err != nil {
			return nil, fmt.Errorf("router /register for %s: %w", shortHex(pubHex), err)
		}
		if cap.MailboxID == "" || cap.ReadSecret == "" || cap.ShardURL == "" {
			return nil, fmt.Errorf("router /register returned an incomplete capability")
		}
		secret, err = hex.DecodeString(cap.ReadSecret)
		if err != nil || len(secret) != 32 {
			return nil, fmt.Errorf("router /register returned a malformed read_secret")
		}
		mailboxIDDisplay = cap.MailboxID
		shard, outRouter = cap.ShardURL, router
		readSecret = cap.ReadSecret
	}

	out := &IdentityRegistration{
		Identity:   identity,
		Pubkey:     pubHex,
		MailboxID:  mailboxIDDisplay,
		ReadSecret: readSecret,
		ShardURL:   shard,
		RouterURL:  outRouter,
	}

	// ── 2. Attach the exact mailbox returned by the selected Router ─────
	// Both protocols use a 16-byte mailbox ID at the transport boundary.
	// FileRelay already returns the real mailbox ID from /register, so there
	// is no second resolve call and no FileTransport-only dependency here.
	// Worker Relay returns the mailbox ID as lowercase hex, so decode it once
	// before handing it to the transport.
	tr, err := m.EnsureRunning(ctx, transportID)
	if err != nil {
		d.Human("[!] Registered, but transport %s is not running (%v).", transportID, err)
		d.Human("    Run transport register-identity again once it starts to attach for receiving.")
		return out, nil
	}

	mailbox, err := hex.DecodeString(mailboxIDDisplay)
	if err != nil || len(mailbox) != 16 {
		return nil, fmt.Errorf("router returned malformed mailbox_id for %s", transportID)
	}
	out.Alias = hex.EncodeToString(mailbox)

	if err := tr.AttachMailbox(ctx, mailbox, secret, shard, router); err != nil {
		d.Human("[!] Registered, but attach failed: %v", err)
		return out, nil
	}
	_ = m.AddAttachment(transportID, ntx.Attachment{
		MailboxID:  out.Alias,
		ReadSecret: readSecret,
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
	d.Human("read_secret:%s", d.Secret(readSecret))
	d.Human("shard:      %s", shard)
	d.Human("")
	d.Human("[i] Peers can now reach you by pubkey. Next: `peer connect <peer>`.")
	return out, nil
}

func canonicalFileRelayRegister(pub []byte, timestamp uint64, nonce [16]byte) []byte {
	const domain = "FR1/REGISTER\x00"
	out := make([]byte, 0, len(domain)+32+8+16)
	out = append(out, domain...)
	out = append(out, pub...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], timestamp)
	out = append(out, b[:]...)
	out = append(out, nonce[:]...)
	return out
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
