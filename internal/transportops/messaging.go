package transportops

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	ntx "github.com/erfanheydarzade/NexTalk/internal/transport"
)

// MessageSendParams encrypts text for a peer and delivers the frame.
type MessageSendParams struct {
	TransportID string // "" falls back to the session relay
	Identity    string // "" falls back to the session identity
	Peer        string // peer ID (encryption session, required)
	Text        string // message text (may be empty with TicketB64)
	TicketB64   string // optional ticket appended as its own line
	MailboxID   string // explicit recipient mailbox hex (address-shared transports)
	ShardURL    string // required with MailboxID
}

// MessageSend encrypts with the session and sends through the active relay.
func MessageSend(d *Deps, p MessageSendParams) error {
	transportID := p.TransportID
	if transportID == "" && d.Session != nil {
		transportID = d.Session.Relay
	}
	if transportID == "" {
		return fmt.Errorf("no relay: pass --via or `use relay` first")
	}
	identity := p.Identity
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	if p.Text == "" && p.TicketB64 == "" {
		return fmt.Errorf("nothing to send: pass message text and/or --ticket")
	}
	cl, err := Client.LoadClient(identity)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	body := p.Text
	if p.TicketB64 != "" {
		if body != "" {
			body += "\n"
		}
		body += p.TicketB64
	}
	cipher, err := cl.Encrypt(p.Peer, []byte(body))
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	Client.SaveClient(cl)
	pub, err := resolveRecipient(p.Peer)
	if err != nil {
		return err
	}
	hint := ntx.RouteHint{RecipientPub: pub, SenderHint: cl.IdentityPublic}
	if p.MailboxID != "" {
		mbox, err := hex.DecodeString(p.MailboxID)
		if err != nil || len(mbox) != 16 {
			return fmt.Errorf("mailbox must be 32 hex chars")
		}
		if p.ShardURL == "" {
			return fmt.Errorf("--shard is required with --mailbox")
		}
		hint = ntx.RouteHint{MailboxID: mbox, ShardURL: p.ShardURL, SenderHint: cl.IdentityPublic}
	} else if addr, ok := peerAddrFor(d, pub); ok {
		// Known explicit address (see `peer address`): address-shared
		// relays cannot route by pubkey, so prefer it over the guess.
		mbox, _ := hex.DecodeString(addr.MailboxID)
		hint = ntx.RouteHint{MailboxID: mbox, ShardURL: addr.ShardURL, SenderHint: cl.IdentityPublic}
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, transportID)
	if err != nil {
		return err
	}
	frame := ntx.WrapFrame(relay.TypeMessage, cipher)
	if err := tr.SendFrame(ctx, frame, hint); err != nil {
		return err
	}
	if d.Session != nil {
		d.Session.RememberPeer(p.Peer)
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"sent": true, "to": p.Peer, "ticket": p.TicketB64 != ""})
	}
	d.Human("✓ Message sent to %s.", shortHex(p.Peer))
	return nil
}

// peerAddrFor returns the session's explicit address for a recipient pub,
// if `peer address` recorded one. Keyed by lowercase hex pubkey.
func peerAddrFor(d *Deps, pub []byte) (shellcmd.PeerAddr, bool) {
	if d == nil || d.Session == nil || len(pub) == 0 {
		return shellcmd.PeerAddr{}, false
	}
	addr, ok := d.Session.PeerMailboxes[strings.ToLower(hex.EncodeToString(pub))]
	return addr, ok && addr.MailboxID != "" && addr.ShardURL != ""
}

type PeerConnectParams struct {
	TransportID string // "" falls back to the session relay
	Identity    string // "" falls back to the session identity
	Peer        string // peer ID (required)
	MailboxID   string // explicit recipient mailbox hex (address-shared transports)
	ShardURL    string // required with MailboxID
}

// PeerConnect creates a handshake offer for a peer and sends it through the
// active relay. The peer answers on their next poll; finish the handshake by
// polling (incoming answers auto-complete the session via shared dispatch).
func PeerConnect(d *Deps, p PeerConnectParams) error {
	transportID := p.TransportID
	if transportID == "" && d.Session != nil {
		transportID = d.Session.Relay
	}
	if transportID == "" {
		return fmt.Errorf("no relay: pass --via or `use relay` first")
	}
	identity := p.Identity
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	cl, err := Client.LoadClient(identity)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	offer, err := cl.CreateOffer(p.Peer)
	if err != nil {
		return fmt.Errorf("offer: %w", err)
	}
	Client.SaveClient(cl)
	pub, err := resolveRecipient(p.Peer)
	if err != nil {
		return err
	}
	hint := ntx.RouteHint{RecipientPub: pub, SenderHint: cl.IdentityPublic}
	if p.MailboxID != "" {
		mbox, err := hex.DecodeString(p.MailboxID)
		if err != nil || len(mbox) != 16 {
			return fmt.Errorf("mailbox must be 32 hex chars")
		}
		if p.ShardURL == "" {
			return fmt.Errorf("--shard is required with --mailbox")
		}
		hint = ntx.RouteHint{MailboxID: mbox, ShardURL: p.ShardURL, SenderHint: cl.IdentityPublic}
	} else if addr, ok := peerAddrFor(d, pub); ok {
		mbox, _ := hex.DecodeString(addr.MailboxID)
		hint = ntx.RouteHint{MailboxID: mbox, ShardURL: addr.ShardURL, SenderHint: cl.IdentityPublic}
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, transportID)
	if err != nil {
		return err
	}
	if err := tr.SendFrame(ctx, ntx.WrapFrame(relay.TypeOffer, offer), hint); err != nil {
		return err
	}
	if d.Session != nil {
		d.Session.RememberPeer(p.Peer)
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"offer_sent": true, "to": p.Peer})
	}
	d.Human("✓ Offer sent to %s — they answer on poll; then `transport poll` to finish.", shortHex(p.Peer))
	return nil
}

// PeerRecordParams stores an explicit relay address for a peer.
type PeerRecordParams struct {
	Peer      string // peer ID or 64-hex pubkey (required)
	MailboxID string // 32 hex recipient mailbox (required)
	ShardURL  string // shard URL (required)
}

// PeerRecord remembers where a peer lives on address-shared relays.
// Without it, offers/answers/messages to that peer fall back to pubkey
// routing, which only works on deterministic transports.
func PeerRecord(d *Deps, p PeerRecordParams) error {
	pub, err := resolveRecipient(p.Peer)
	if err != nil {
		return err
	}
	mbox, err := hex.DecodeString(p.MailboxID)
	if err != nil || len(mbox) != 16 {
		return fmt.Errorf("mailbox must be 32 hex chars")
	}
	if p.ShardURL == "" {
		return fmt.Errorf("--shard is required")
	}
	if d.Session == nil {
		return fmt.Errorf("no session")
	}
	if d.Session.PeerMailboxes == nil {
		d.Session.PeerMailboxes = map[string]shellcmd.PeerAddr{}
	}
	d.Session.PeerMailboxes[strings.ToLower(hex.EncodeToString(pub))] = shellcmd.PeerAddr{
		PeerID: p.Peer, MailboxID: strings.ToLower(hex.EncodeToString(mbox)), ShardURL: p.ShardURL,
	}
	d.Session.RememberPeer(p.Peer)
	if d.JSON {
		return d.JSONOut(map[string]any{"peer": p.Peer, "mailbox_id": strings.ToLower(hex.EncodeToString(mbox)), "shard_url": p.ShardURL})
	}
	d.Human("Address recorded for %s.", shortHex(p.Peer))
	return nil
}
