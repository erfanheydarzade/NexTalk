// Package core implements the NexTalk handshake protocol.
//
// Dependency order (innermost → outermost):
//
//	crypto  ←  core/engine  ←  client
//
// Engine is a *stateless* protocol processor. It owns no identity, holds no
// sessions, and never touches the file system. All mutable state lives in
// client.Client; the Engine only knows about the crypto package below it.
//
// Callers pass in key material and get back new/mutated state to persist.
package core

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"
)

// Engine is a stateless protocol processor.
// Create one with NewEngine(); it is safe to reuse and share across goroutines
// (it has no mutable fields).
type Engine struct{}

// NewEngine returns a ready Engine.
func NewEngine() *Engine { return &Engine{} }

// newPeer creates a fresh ephemeral SecurePeer seeded with the caller's
// long-term identity keys. All short-term key material (X25519, DH, Kyber768)
// is newly generated on each call.
//
// This is an internal helper; only CreateOffer and AcceptOffer call it.
func (e *Engine) newPeer(
	expectedPeerHash []byte,
	idPriv ed25519.PrivateKey,
	idPub ed25519.PublicKey,
	dilPriv, dilPub []byte,
) (*crypto.SecurePeer, error) {
	privX, pubX := crypto.GenerateX25519KeyPair()
	dhPrivX, dhPubX := crypto.GenerateX25519KeyPair()

	pqcPubObj, pqcPrivObj, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kyber768 keygen: %w", err)
	}
	pqcPubBytes, _ := pqcPubObj.MarshalBinary()
	pqcPrivBytes, _ := pqcPrivObj.MarshalBinary()

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
	}, nil
}

// ── Step 1 ───────────────────────────────────────────────────────────────────

// CreateOffer builds a signed offer payload for the initiator to send to a peer.
//
// Returns:
//   - peer: the ephemeral session state; the caller MUST store this as
//     sessions["pending_<peerId>"] (and sessions["pending"]) before the
//     answer arrives, so FinishHandshake can retrieve it.
//   - offerJSON: the wire bytes to forward to the peer.
func (e *Engine) CreateOffer(
	myId string,
	idPriv ed25519.PrivateKey,
	idPub ed25519.PublicKey,
	dilPriv, dilPub []byte,
	peerId string,
) (peer *crypto.SecurePeer, offerJSON []byte, err error) {
	peer, err = e.newPeer(nil, idPriv, idPub, dilPriv, dilPub)
	if err != nil {
		return nil, nil, err
	}

	peerIdBytes, err := base58.Decode(peerId)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid peer ID encoding: %w", err)
	}

	offerId := crypto.GenerateOfferID()
	offer := HandShakeOffer{
		SenderId:      myId,
		RecipientId:   peerIdBytes,
		OfferID:       offerId,
		IdPub:         peer.IdentityPublicBytes(),
		Pub:           peer.PublicBytes(),
		DhPub:         peer.DhPubBytes(),
		KyberPub:      peer.PqcPubBytes(),
		DilithiumPub:  peer.PqcSignPublic,
		Sign:          peer.GetSign(offerId, peerIdBytes),
		DilithiumSign: peer.GetDilithiumSign(offerId, peerIdBytes),
	}

	offerJSON, err = json.Marshal(offer)
	return peer, offerJSON, err
}

// ── Step 2 ───────────────────────────────────────────────────────────────────

// AcceptOffer validates the initiator's offer, performs the responder-side KEM
// encapsulation, runs Handshake, and returns an answer for the initiator.
//
// existingSessions is the caller's current session map, used only for replay
// detection (SeenOffers) — it is never modified here; the caller stores the
// returned peer.
//
// Returns:
//   - senderID: the initiator's peer ID; the caller stores peer under this key.
//   - peer:     the fully initialised responder session.
//   - answerJSON: the wire bytes to send back to the initiator.
func (e *Engine) AcceptOffer(
	myId string,
	idPriv ed25519.PrivateKey,
	idPub ed25519.PublicKey,
	dilPriv, dilPub []byte,
	existingSessions map[string]*crypto.SecurePeer,
	offerBytes []byte,
) (senderID string, peer *crypto.SecurePeer, answerJSON []byte, err error) {
	var offer HandShakeOffer
	if err = json.Unmarshal(offerBytes, &offer); err != nil {
		return "", nil, nil, fmt.Errorf("unmarshal offer: %w", err)
	}
	if len(offer.OfferID) == 0 {
		return "", nil, nil, fmt.Errorf("missing offer id")
	}
	if base58.Encode(offer.RecipientId) != myId {
		return "", nil, nil, fmt.Errorf("offer not intended for this peer")
	}

	// Identity binding: sender ID must be derivable from the supplied public keys.
	if crypto.DerivePeerID(offer.IdPub, offer.DilithiumPub) != offer.SenderId {
		return "", nil, nil, fmt.Errorf("sender ID spoofing detected: keys do not match claimed ID")
	}

	// Replay detection.
	offerIDKey := base58.Encode(offer.OfferID)
	if existing, exists := existingSessions[offer.SenderId]; exists {
		if existing.SeenOffers != nil && existing.SeenOffers[offerIDKey] {
			return "", nil, nil, fmt.Errorf("offer replay detected for peer %s", offer.SenderId)
		}
	}

	responderPeer, err := e.newPeer(nil, idPriv, idPub, dilPriv, dilPub)
	if err != nil {
		return "", nil, nil, err
	}

	// Carry forward seen-offer history so re-keying doesn't lose replay protection.
	if existing, exists := existingSessions[offer.SenderId]; exists && existing.SeenOffers != nil {
		for k, v := range existing.SeenOffers {
			responderPeer.SeenOffers[k] = v
		}
	}
	responderPeer.SeenOffers[offerIDKey] = true

	// KEM: encapsulate against initiator's Kyber768 public key.
	scheme := kyber768.Scheme()
	remoteKyberPub, err := scheme.UnmarshalBinaryPublicKey(offer.KyberPub)
	if err != nil {
		return "", nil, nil, fmt.Errorf("unmarshal kyber public key: %w", err)
	}
	ciphertext, sharedSecret, err := scheme.Encapsulate(remoteKyberPub)
	if err != nil {
		return "", nil, nil, fmt.Errorf("kyber encapsulate: %w", err)
	}

	myIdBytes, _ := base58.Decode(myId)
	if err = responderPeer.Handshake(
		offer.IdPub, offer.Pub, offer.DhPub,
		offer.KyberPub, offer.DilithiumPub,
		offer.Sign, offer.DilithiumSign,
		sharedSecret, offer.OfferID, myIdBytes,
	); err != nil {
		return "", nil, nil, fmt.Errorf("handshake (responder): %w", err)
	}

	senderIdBytes, err := base58.Decode(offer.SenderId)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid sender id encoding: %w", err)
	}

	answer := HandShakeAnswer{
		SenderId:        myId,
		IdPub:           responderPeer.IdentityPublicBytes(),
		Pub:             responderPeer.PublicBytes(),
		DhPub:           responderPeer.DhPubBytes(),
		KyberPub:        responderPeer.PqcPubBytes(),
		KyberCiphertext: ciphertext,
		DilithiumPub:    responderPeer.PqcSignPublic,
		Sign:            responderPeer.GetSign(offer.OfferID, senderIdBytes),
		DilithiumSign:   responderPeer.GetDilithiumSign(offer.OfferID, senderIdBytes),
		OfferID:         offer.OfferID,
		RecipientId:     myIdBytes,
	}

	answerJSON, err = json.Marshal(answer)
	return offer.SenderId, responderPeer, answerJSON, err
}

// ── Step 3 ───────────────────────────────────────────────────────────────────

// FinishHandshake completes the initiator-side handshake.
//
// KEM flow (initiator side):
//  1. Decapsulate the responder's KyberCiphertext using our Kyber768 private key.
//  2. Feed the recovered sharedSecret into Handshake — must match the responder's value.
//
// pendingPeer is modified in place (Handshake writes session keys into it).
// The caller is responsible for moving it from sessions["pending_<id>"] to sessions[peerID].
//
// Returns peerID so the caller knows which key to use in the sessions map.
func (e *Engine) FinishHandshake(
	myId string,
	pendingPeer *crypto.SecurePeer,
	answerBytes []byte,
) (peerID string, err error) {
	var answer HandShakeAnswer
	if err = json.Unmarshal(answerBytes, &answer); err != nil {
		return "", fmt.Errorf("unmarshal answer: %w", err)
	}
	if len(answer.KyberCiphertext) == 0 {
		return "", fmt.Errorf("answer missing PQC ciphertext")
	}

	// Identity binding: the claimed SenderId must be derivable from the
	// supplied public keys. SenderId is not part of the signed handshake
	// message, so without this check a malicious/compromised responder
	// (or a hostile transport) could sign with its own real keys while
	// claiming to be an arbitrary peer ID, causing the caller to file this
	// session under the wrong peer and silently hijack that relationship.
	if crypto.DerivePeerID(answer.IdPub, answer.DilithiumPub) != answer.SenderId {
		return "", fmt.Errorf("sender ID spoofing detected in answer: keys do not match claimed ID")
	}

	// KEM: recover the shared secret the responder encapsulated for us.
	scheme := kyber768.Scheme()
	kyberPriv, err := scheme.UnmarshalBinaryPrivateKey(pendingPeer.PqcPrivateKey)
	if err != nil {
		return "", fmt.Errorf("unmarshal kyber private key: %w", err)
	}
	sharedSecret, err := scheme.Decapsulate(kyberPriv, answer.KyberCiphertext)
	if err != nil {
		return "", fmt.Errorf("kyber decapsulate: %w", err)
	}

	myIdBytes, err := base58.Decode(myId)
	if err != nil {
		return "", fmt.Errorf("decode client id: %w", err)
	}

	if err = pendingPeer.Handshake(
		answer.IdPub, answer.Pub, answer.DhPub,
		answer.KyberPub, answer.DilithiumPub,
		answer.Sign, answer.DilithiumSign,
		sharedSecret, answer.OfferID, myIdBytes,
	); err != nil {
		return "", fmt.Errorf("handshake (initiator): %w", err)
	}

	return answer.SenderId, nil
}
