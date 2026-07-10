package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/erfanheydarzade/NexTalk/crypto"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/ed25519"
)

// Client represents a local user identity and all active secure sessions.
type Client struct {
	Id               string                        `json:"id"`
	IdentityPrivate  ed25519.PrivateKey            `json:"identityPrivate"`
	IdentityPublic   ed25519.PublicKey             `json:"identityPublic"`
	DilithiumPrivate []byte                        `json:"dilithiumPrivate"` // ← long-term PQC signing key
	DilithiumPublic  []byte                        `json:"dilithiumPublic"`  // ← used in ID derivation
	Sessions         map[string]*crypto.SecurePeer `json:"sessions"`
}

func (c *Client) Decrypt(payloadBytes []byte) (string, []byte, error) {
	var msgHeader struct {
		SenderID string `json:"s"`
	}
	if err := json.Unmarshal(payloadBytes, &msgHeader); err != nil {
		return "", nil, fmt.Errorf("error parsing message header: %v", err)
	}
	if msgHeader.SenderID == "" {
		return "", nil, fmt.Errorf("message lacks a sender identifier (senderID)")
	}

	peerSession, exists := c.Sessions[msgHeader.SenderID]
	if !exists {
		return "", nil, fmt.Errorf("no active session with user '%s' exists", msgHeader.SenderID)
	}

	return peerSession.Decrypt(payloadBytes)
}

// NewClient creates a fresh cryptographic identity.
//
// FIX: corrected comment — DerivePeerID encodes with Base58, not hex.
// Id = base58( Ed25519IdentityPublic + sha3_256(DilithiumPublic) )
func NewClient() *Client {
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	dilPriv, dilPub := crypto.GenerateDilithiumKeyPair()

	return &Client{
		Id:               crypto.DerivePeerID(pubEd, dilPub),
		IdentityPrivate:  privEd,
		IdentityPublic:   pubEd,
		DilithiumPrivate: dilPriv,
		DilithiumPublic:  dilPub,
		Sessions:         make(map[string]*crypto.SecurePeer),
	}
}

// SaveClient persists the full client identity — including long-term
// Ed25519/Dilithium private keys and every active SecurePeer session
// (root keys, chain keys, HMAC keys, file keys) — to disk as JSON.
//
// FIX (critical): changed file mode from 0644 (world-readable) to 0600
// (owner read/write only). The previous mode allowed any other local
// user on a shared/multi-user system to read this file directly and
// extract the full identity plus every active session's key material —
// a complete compromise of past and future traffic for this client,
// not just a single message.
func SaveClient(cl *Client) {
	filename := fmt.Sprintf("%s.json", cl.Id)
	data, err := json.MarshalIndent(cl, "", "  ")
	if err != nil {
		fmt.Printf("[-] Failed to serialize client %s: %v\n", cl.Id, err)
		return
	}

	// Write with restrictive permissions from the start. Note: if the
	// file already exists with looser permissions from a prior (pre-fix)
	// run, os.WriteFile does NOT change the mode of an existing file on
	// all platforms/edge cases — see the explicit Chmod below as a
	// belt-and-suspenders fix for upgrades from vulnerable versions.
	if err := os.WriteFile(filename, data, 0600); err != nil {
		fmt.Printf("[-] Failed to write client file %s: %v\n", filename, err)
		return
	}
	if err := os.Chmod(filename, 0600); err != nil {
		fmt.Printf("[-] Failed to enforce permissions on %s: %v\n", filename, err)
	}
}

// NewSecurePeer initializes a new secure session state for a peer.
func NewSecurePeer(expectedPeerHash []byte, idPriv ed25519.PrivateKey, idPub ed25519.PublicKey, dilPriv, dilPub []byte) *crypto.SecurePeer {
	privX, pubX := crypto.GenerateX25519KeyPair()
	dhPrivX, dhPubX := crypto.GenerateX25519KeyPair()

	pqcPubObj, pqcPrivObj, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}
	pqcPubBytes, err := pqcPubObj.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pqcPrivBytes, err := pqcPrivObj.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return &crypto.SecurePeer{
		ExpectedPeerHash: expectedPeerHash,
		IdentityPrivate:  idPriv,
		IdentityPublic:   idPub,
		Private:          privX,
		Public:           pubX,
		PqcPrivateKey:    pqcPrivBytes,
		PqcPublicKey:     pqcPubBytes,
		DhPrivate:        dhPrivX,
		DhPublic:         dhPubX,
		PqcSignPrivate:   dilPriv,
		PqcSignPublic:    dilPub,
		SkippedMessages:  make(map[string][]byte),
		SeenOffers:       make(map[string]bool),
	}
}
