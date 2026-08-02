// internal/relay/relay.go
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Message Relay is the single interface every transport backend must satisfy.
// It deliberately knows nothing about handshake logic or encryption —
// those live in core.Engine. Relay only moves opaque bytes.
type Message struct {
	Body []byte
}

// SenderAuth proves the caller of Send controls the private key for
// SenderAuth.PubKey. As of the v2 capability architecture, this signs a
// message that binds sender identity, the RECIPIENT'S OPAQUE MAILBOX ID
// (never their pubkey — the shard never learns that), and the exact
// message content together, so a captured auth can't be replayed against a
// different mailbox or with swapped message bytes.
//
// Build one with BuildSenderAuth rather than constructing it by hand —
// every caller (CLI commands, the GUI, anything else) MUST sign the exact
// same message format below, or the shard will reject it as an invalid
// signature. Centralizing this in one function is what guarantees that.
type SenderAuth struct {
	PubKey    string `json:"pubkey"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

// BuildSenderAuth signs the message a shard's /send handler verifies:
//
//	send:{senderPubkeyLowerHex}:{recipientMailboxIdLowerHex}:{timestamp}:{sha256hex(payload)}
//
// senderPriv must be the full 64-byte ed25519.PrivateKey (seed + public
// key), i.e. Client.IdentityPrivate — not just the 32-byte seed.
// recipientMailboxID is the opaque mailbox id resolved for the recipient's
// pubkey via Router /register (own mailbox) or /resolve (a peer's), NEVER
// the recipient's raw pubkey — shards must never see that.
//
// This is the ONE place this signing scheme is implemented. Every caller
// should call this instead of reimplementing the signed-message format.
func BuildSenderAuth(senderPriv ed25519.PrivateKey, recipientMailboxID string, payload []byte) (SenderAuth, error) {
	pub, ok := senderPriv.Public().(ed25519.PublicKey)
	if !ok {
		return SenderAuth{}, fmt.Errorf("relay: invalid ed25519 private key")
	}
	senderHex := hex.EncodeToString(pub)
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	msgHash := sha256.Sum256(payload)
	msgHashHex := hex.EncodeToString(msgHash[:])

	signedMessage := fmt.Sprintf("send:%s:%s:%s:%s", senderHex, strings.ToLower(recipientMailboxID), timestamp, msgHashHex)
	sig := ed25519.Sign(senderPriv, []byte(signedMessage))

	return SenderAuth{
		PubKey:    senderHex,
		Timestamp: timestamp,
		Signature: hex.EncodeToString(sig),
	}, nil
}

// MailboxCapability is what an Adapter caches internally, forever, after
// registering an identity via Router /register. Not part of the public
// Relay interface — callers keep using Register/Send/Receive exactly as
// before; this type only appears inside adapter.go's own cache.
type MailboxCapability struct {
	MailboxID  string `json:"mailbox_id"`
	ReadSecret string `json:"read_secret"`
	ShardURL   string `json:"shard_url"`
	// ReplicaShardURLs is the full replica set for this mailbox, primary
	// first (== ShardURL). Populated by Router /register as of v2.2;
	// empty/nil on a v2.1 Router (REPLICATION_FACTOR effectively 1) —
	// callers should treat that as "no fallback available" rather than
	// an error.
	ReplicaShardURLs []string `json:"replica_shard_urls,omitempty"`
	ExpiresAt        int64    `json:"expires_at"`
	TableVersion     int      `json:"table_version"`
}

// PeerResolution is what an Adapter caches internally, forever (per peer),
// after resolving a contacts's pubkey via Router /resolve. Also internal —
// not part of the public Relay interface.
type PeerResolution struct {
	MailboxID string `json:"mailbox_id"`
	ShardURL  string `json:"shard_url"`
	// ReplicaShardURLs mirrors MailboxCapability.ReplicaShardURLs — see
	// that field's comment. Same v2.1-Router caveat applies.
	ReplicaShardURLs []string `json:"replica_shard_urls,omitempty"`
	TableVersion     int      `json:"table_version"`
}

// ShardIdentity pairs a shard's public URL with the Ed25519 public key it
// proved ownership of during self-registration (see Router
// /register_shard). Pubkey is empty for shards that were added manually to
// SHARD_URLS and never self-registered — those can still serve normal
// client Send/Read traffic, they just can't be a verified origin for a
// shard-to-shard /internal/replicate push (see shard/worker.js
// handleReplicate), since there's no key on file to check that signature
// against.
type ShardIdentity struct {
	URL    string `json:"url"`
	Pubkey string `json:"pubkey"`
}

// RoutingTable is the signed, cacheable document served at
// GET {router}/routing_table.json. Fetched rarely (on expiry or version
// bump) by an Adapter internally.
type RoutingTable struct {
	Version     int      `json:"version"`
	GeneratedAt int64    `json:"generated_at"`
	ExpiresAt   int64    `json:"expires_at"`
	Algorithm   string   `json:"algorithm"`
	ShardURLs   []string `json:"shard_urls"`
	// Shards is ShardURLs paired with each shard's self-registered
	// identity pubkey, when it has one. Added in v2.2 alongside
	// replication; a v2.1 client that ignores this field still works fine.
	Shards []ShardIdentity `json:"shards,omitempty"`
	// ReplicationFactor is how many shards each mailbox's messages are
	// spread across (see Router REPLICATION_FACTOR). 1 (or 0 from an old
	// Router) means no replication — every mailbox has exactly one shard.
	ReplicationFactor int    `json:"replication_factor,omitempty"`
	PriorShardCounts  []int  `json:"prior_shard_counts"`
	RouterPublicKey   string `json:"router_public_key"`
	Signature         string `json:"signature"`
}

// Expired reports whether a cached RoutingTable should be refetched.
func (rt *RoutingTable) Expired() bool {
	return rt == nil || time.Now().UnixMilli() > rt.ExpiresAt
}

// Relay is the single interface every transport backend must satisfy. It
// deliberately knows nothing about handshake logic, encryption, or (as of
// the v2 capability architecture) mailbox IDs / read secrets / shard
// topology — those are all Adapter-internal concerns now. Callers still
// only ever deal in pubkeys and raw payloads, exactly as before.
type Relay interface {
	// Register proves ownership of privateKey to the Router (minting or
	// reusing a cached mailbox capability behind the scenes) and returns
	// the identity's own pubkey as lowercase hex, same as v1.
	Register(ctx context.Context, privateKey []byte) (string, error)
	// Send signs and transmits payload to recipientPubKey. senderPriv is
	// the caller's own identity private key. Internally this resolves
	// recipientPubKey to its (cached) opaque mailbox_id/shard via the
	// Router and talks to that shard directly — the caller never sees any
	// of that.
	Send(ctx context.Context, recipientPubKey []byte, payload []byte, senderPriv ed25519.PrivateKey) error
	// Receive reads (and drains) privateKey's own mailbox. Internally uses
	// a cached capability obtained via Register — call Register at least
	// once for this identity first (as before).
	Receive(ctx context.Context, privateKey []byte) ([]Message, error)
}

// ---- Envelope ---------------------------------------------------------------

// Type is the discriminator for the three payload kinds in the protocol.
type Type byte

const (
	TypeOffer   Type = 0x01
	TypeAnswer  Type = 0x02
	TypeMessage Type = 0x03
)

// Envelope is the common wire wrapper used by all relay implementations.
type Envelope struct {
	Type Type            `json:"type"`
	Data json.RawMessage `json:"data"`
}
