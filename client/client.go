// Package client is the top-level session manager for a NexTalk identity.
//
// Dependency order:
//
//	crypto  ←  core/engine  ←  client   ← cmd / transport layers
//
// Client owns: long-term identity keys, the active session map, and
// persistence (disk I/O).  Protocol logic is delegated to the embedded
// *core.Engine; Client never touches crypto primitives directly.
//
// Contacts are NOT owned by Client — they live in internal/contacts as a
// single global store shared across every profile on the machine, so the
// contact book can be managed with or without an active/loaded client.
package client

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"golang.org/x/crypto/ed25519"
)

// Client represents a local user identity and all active secure sessions.
//
// The eng field is not serialised; it is re-injected by NewClient and
// LoadClient.  Engine is stateless so a single shared instance is fine.
type Client struct {
	Id               string                        `json:"id"`
	IdentityPrivate  ed25519.PrivateKey            `json:"identityPrivate"`
	IdentityPublic   ed25519.PublicKey             `json:"identityPublic"`
	DilithiumPrivate []byte                        `json:"dilithiumPrivate"`
	DilithiumPublic  []byte                        `json:"dilithiumPublic"`
	Sessions         map[string]*crypto.SecurePeer `json:"sessions"`

	eng *core.Engine // not serialised; injected on construction/load
}

// ── Construction & persistence ────────────────────────────────────────────────

// NewClient generates a fresh cryptographic identity and wires up the engine.
//
// Id = base58( Ed25519IdentityPublic[32] + sha3_256(DilithiumPublic)[32] )
func NewClient() *Client {
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	dilPriv, dilPub := crypto.GenerateDilithiumKeyPair()
	SaveClient(&Client{
		Id:               crypto.DerivePeerID(pubEd, dilPub),
		IdentityPrivate:  privEd,
		IdentityPublic:   pubEd,
		DilithiumPrivate: dilPriv,
		DilithiumPublic:  dilPub,
		Sessions:         make(map[string]*crypto.SecurePeer),
		eng:              core.NewEngine(),
	})

	return &Client{
		Id:               crypto.DerivePeerID(pubEd, dilPub),
		IdentityPrivate:  privEd,
		IdentityPublic:   pubEd,
		DilithiumPrivate: dilPriv,
		DilithiumPublic:  dilPub,
		Sessions:         make(map[string]*crypto.SecurePeer),
		eng:              core.NewEngine(),
	}
}

// LoadClient reads a persisted client from <id>.json and re-injects the engine.
func LoadClient(id string) (*Client, error) {
	filename := fmt.Sprintf("%s.json", id)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cl Client
	if err := json.Unmarshal(data, &cl); err != nil {
		return nil, err
	}
	cl.eng = core.NewEngine()
	return &cl, nil
}

// NewClientFromKeys wraps an existing identity (already generated or
// imported) in a *Client with the engine wired up. Use this when the
// caller owns the key material and persistence — e.g. the wasm build,
// which has no filesystem for SaveClient/LoadClient.
func NewClientFromKeys(id string, privEd ed25519.PrivateKey, pubEd ed25519.PublicKey, dilPriv, dilPub []byte, sessions map[string]*crypto.SecurePeer) *Client {
	return &Client{
		Id:               id,
		IdentityPrivate:  privEd,
		IdentityPublic:   pubEd,
		DilithiumPrivate: dilPriv,
		DilithiumPublic:  dilPub,
		Sessions:         sessions,
		eng:              core.NewEngine(),
	}
}

// SaveClient persists the full client state (identity keys + every active
// session) to <id>.json with owner-only permissions (0600).
//
// The 0600 mode prevents other local users from reading key material.
// The explicit Chmod is belt-and-suspenders for files that may have been
// created with looser permissions by older versions.
func SaveClient(cl *Client) {
	filename := fmt.Sprintf("%s.json", cl.Id)
	data, err := json.MarshalIndent(cl, "", "  ")
	if err != nil {
		fmt.Printf("[-] Failed to serialize client %s: %v\n", cl.Id, err)
		return
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		fmt.Printf("[-] Failed to write client file %s: %v\n", filename, err)
		return
	}
	if err := os.Chmod(filename, 0600); err != nil {
		fmt.Printf("[-] Failed to enforce permissions on %s: %v\n", filename, err)
	}
}

// ── Handshake protocol (delegates to Engine) ──────────────────────────────────

// CreateOffer (Step 1) builds a signed offer for the given peer and returns
// the JSON bytes to forward.  The ephemeral session is stored as pending so
// FinishHandshake can retrieve it when the answer arrives.
func (c *Client) CreateOffer(peerId string) ([]byte, error) {
	peer, offerJSON, err := c.eng.CreateOffer(
		c.Id, c.IdentityPrivate, c.IdentityPublic,
		c.DilithiumPrivate, c.DilithiumPublic,
		peerId,
	)
	if err != nil {
		return nil, err
	}
	// Store under both keys so FinishHandshake can find it whether or not
	// the caller remembered the peer ID at answer time.
	if peerId != "" {
		c.Sessions["pending_"+peerId] = peer
	}
	c.Sessions["pending"] = peer
	SaveClient(c)
	return offerJSON, nil
}

// AcceptOffer (Step 2) validates the offer, completes the responder side of
// the handshake, stores the session, and returns the answer JSON to forward.
func (c *Client) AcceptOffer(offerBytes []byte) ([]byte, error) {
	senderID, peer, answerJSON, err := c.eng.AcceptOffer(
		c.Id, c.IdentityPrivate, c.IdentityPublic,
		c.DilithiumPrivate, c.DilithiumPublic,
		c.Sessions, offerBytes,
	)
	if err != nil {
		return nil, err
	}
	c.Sessions[senderID] = peer
	SaveClient(c)
	return answerJSON, nil
}

// FinishHandshake (Step 3) completes the initiator-side handshake.
// It locates the pending peer, passes it to the Engine (which modifies it in
// place), then promotes it to a permanent session under the peer's ID.
// Returns the peer's canonical ID.
func (c *Client) FinishHandshake(answerBytes []byte) (string, error) {
	// Peek at the sender ID so we can locate the right pending peer.
	// Works for both wire encodings (nanopack current, legacy JSON).
	hdr, err := core.PeekAnswerSenderID(answerBytes)
	if err != nil {
		return "", fmt.Errorf("peek answer header: %w", err)
	}

	peer, ok := c.Sessions["pending_"+hdr]
	if !ok {
		peer, ok = c.Sessions["pending"]
		if !ok {
			return "", fmt.Errorf("no pending session found for %s", hdr)
		}
	}

	// Engine modifies peer in place (writes session keys).
	peerID, err := c.eng.FinishHandshake(c.Id, peer, answerBytes)
	if err != nil {
		return "", err
	}

	delete(c.Sessions, "pending")
	delete(c.Sessions, "pending_"+peerID)
	c.Sessions[peerID] = peer
	SaveClient(c)
	return peerID, nil
}

// ── Message I/O (no engine needed — SecurePeer handles this directly) ─────────

// Encrypt (Step 4) encrypts a message for an established session.
// Client calls SecurePeer.Encrypt directly — no engine hop needed because
// this is pure ratchet crypto with no handshake state transitions.
func (c *Client) Encrypt(peerID string, message []byte) ([]byte, error) {
	session, ok := c.Sessions[peerID]
	if !ok {
		return nil, fmt.Errorf("session not found for peer %s", peerID)
	}
	ciphertext, err := session.Encrypt(c.Id, message)
	if err != nil {
		return nil, err
	}
	SaveClient(c)
	return ciphertext, nil
}

// Decrypt (Step 5) decrypts a raw message payload (not base64).
// The sender ID is read from the message header and used to look up the
// correct SecurePeer session.
func (c *Client) Decrypt(payloadBytes []byte) (string, []byte, error) {
	// The claimed sender only selects the session; it is authenticated by
	// the HMAC check inside SecurePeer.Decrypt below.
	claimedSender, err := crypto.SenderIDFromFrame(payloadBytes)
	if err != nil {
		return "", nil, err
	}

	session, exists := c.Sessions[claimedSender]
	if !exists {
		return "", nil, fmt.Errorf("no active session with user '%s'", claimedSender)
	}
	senderID, plaintext, err := session.Decrypt(payloadBytes)
	if err != nil {
		return "", nil, err
	}
	SaveClient(c)
	return senderID, plaintext, nil
}
