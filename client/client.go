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
// ID = hex(Ed25519Public) + sha3_256(DilithiumPublic)
// هر دو کلید long-term هستن و در Client ذخیره می‌شن.
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

func SaveClient(cl *Client) {
	filename := fmt.Sprintf("%s.json", cl.Id)
	data, err := json.MarshalIndent(cl, "", "  ")
	if err != nil {
		fmt.Printf("[-] Failed to serialize client %s: %v\n", cl.Id, err)
		return
	}
	_ = os.WriteFile(filename, data, 0644)
}

// NewSecurePeer initializes a new secure session state for a peer.
//
// Dilithium keys از Client می‌گیره (long-term) نه اینکه هر بار جدید بسازه —
// چون ID peer به همون کلیدهای ثابت بسته‌ست.
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
		PqcPrivateKey:    pqcPrivBytes, // Kyber768 — هر session جدید
		PqcPublicKey:     pqcPubBytes,
		DhPrivate:        dhPrivX,
		DhPublic:         dhPubX,
		PqcSignPrivate:   dilPriv, // ← از Client می‌گیره، ثابت
		PqcSignPublic:    dilPub,
		SkippedMessages:  make(map[string][]byte),
		SeenOffers:       make(map[string]bool),
	}
}
