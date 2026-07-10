package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/mr-tron/base58"
)

type Engine struct {
	Client *Client.Client
}

// NewEngine initializes the API with a client
func NewEngine(c *Client.Client) *Engine {
	return &Engine{Client: c}
}

// CreateOffer (Step 1) - Generates a Base64 string to send to a friend.
func (of *Engine) CreateOffer(peerId string) ([]byte, error) {
	newPeer := Client.NewSecurePeer(
		nil,
		of.Client.IdentityPrivate,
		of.Client.IdentityPublic,
		of.Client.DilithiumPrivate,
		of.Client.DilithiumPublic,
	)

	peerIdBytes, err := base58.Decode(peerId)
	if err != nil {
		return nil, fmt.Errorf("invalid peer ID encoding: %w", err)
	}

	offerId := crypto.GenerateOfferID()
	offer := Client.HandshakeOffer{
		SenderId:      of.Client.Id,
		RecipientId:   peerIdBytes,
		OfferID:       offerId,
		IdPub:         newPeer.IdentityPublicBytes(),
		Pub:           newPeer.PublicBytes(),
		DhPub:         newPeer.DhPubBytes(),
		KyberPub:      newPeer.PqcPubBytes(),
		DilithiumPub:  newPeer.PqcSignPublic,
		Sign:          newPeer.GetSign(offerId, peerIdBytes),
		DilithiumSign: newPeer.GetDilithiumSign(offerId, peerIdBytes),
	}

	if peerId != "" {
		of.Client.Sessions["pending_"+peerId] = newPeer
	}
	of.Client.Sessions["pending"] = newPeer

	Client.SaveClient(of.Client)
	return json.Marshal(offer)
}

// AcceptOffer (Step 2) - Processes a friend's offer and generates an Answer JSON.
//
// KEM flow (responder side):
//  1. Unmarshal the initiator's Kyber768 public key from the offer.
//  2. Encapsulate → produces (ciphertext, sharedSecret).
//  3. ciphertext is sent back inside HandshakeAnswer so the initiator can decapsulate.
//  4. sharedSecret is fed into Handshake() for session key derivation.
func (of *Engine) AcceptOffer(offerBytes []byte) ([]byte, error) {
	var offer Client.HandshakeOffer
	if err := json.Unmarshal(offerBytes, &offer); err != nil {
		return nil, fmt.Errorf("unmarshal offer: %w", err)
	}

	if len(offer.OfferID) == 0 {
		return nil, fmt.Errorf("missing offer id")
	}

	if base58.Encode(offer.RecipientId) != of.Client.Id {
		return nil, fmt.Errorf("offer not intended for this peer")
	}

	// Bind claimed SenderId to the actual identity keys (prevents spoofing).
	derivedSenderId := crypto.DerivePeerID(offer.IdPub, offer.DilithiumPub)
	if derivedSenderId != offer.SenderId {
		return nil, fmt.Errorf("sender ID spoofing detected: id does not match identity public key")
	}

	offerIDKey := base58.Encode(offer.OfferID)

	if existingPeer, exists := of.Client.Sessions[offer.SenderId]; exists {
		if existingPeer.SeenOffers != nil && existingPeer.SeenOffers[offerIDKey] {
			return nil, fmt.Errorf("offer replay detected for peer %s", offer.SenderId)
		}
	}

	responderPeer := Client.NewSecurePeer(
		nil,
		of.Client.IdentityPrivate,
		of.Client.IdentityPublic,
		of.Client.DilithiumPrivate,
		of.Client.DilithiumPublic,
	)

	// FIX: guarantee a non-nil map before any write, regardless of what
	// NewSecurePeer does internally. This is the primary defense against
	// the nil-map-write panic (DoS via first-contact offer).
	if responderPeer.SeenOffers == nil {
		responderPeer.SeenOffers = make(map[string]bool)
	}

	if existingPeer, exists := of.Client.Sessions[offer.SenderId]; exists && existingPeer.SeenOffers != nil {
		for k, v := range existingPeer.SeenOffers {
			responderPeer.SeenOffers[k] = v
		}
	}

	responderPeer.SeenOffers[offerIDKey] = true

	scheme := kyber768.Scheme()
	remoteKyberPub, err := scheme.UnmarshalBinaryPublicKey(offer.KyberPub)
	if err != nil {
		return nil, fmt.Errorf("unmarshal kyber public key: %w", err)
	}

	ciphertext, sharedSecret, err := scheme.Encapsulate(remoteKyberPub)
	if err != nil {
		return nil, fmt.Errorf("kyber encapsulate: %w", err)
	}

	clientIdByte, err := base58.Decode(of.Client.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid own client id encoding: %w", err)
	}

	if err := responderPeer.Handshake(
		offer.IdPub,
		offer.Pub,
		offer.DhPub,
		offer.KyberPub,
		offer.DilithiumPub,
		offer.Sign,
		offer.DilithiumSign,
		sharedSecret,
		offer.OfferID,
		clientIdByte,
	); err != nil {
		return nil, fmt.Errorf("handshake (responder): %w", err)
	}

	of.Client.Sessions[offer.SenderId] = responderPeer
	Client.SaveClient(of.Client)

	senderIdBytes, err := base58.Decode(offer.SenderId)
	if err != nil {
		return nil, fmt.Errorf("invalid sender id encoding: %w", err)
	}

	answer := Client.HandshakeAnswer{
		SenderId:        of.Client.Id,
		IdPub:           responderPeer.IdentityPublicBytes(),
		Pub:             responderPeer.PublicBytes(),
		DhPub:           responderPeer.DhPubBytes(),
		KyberPub:        responderPeer.PqcPubBytes(),
		KyberCiphertext: ciphertext,
		DilithiumPub:    responderPeer.PqcSignPublic,
		Sign:            responderPeer.GetSign(offer.OfferID, senderIdBytes),
		DilithiumSign:   responderPeer.GetDilithiumSign(offer.OfferID, senderIdBytes),
		OfferID:         offer.OfferID,
		RecipientId:     clientIdByte,
	}

	return json.Marshal(answer)
}

// FinishHandshake (Step 3) - Finalizes the session on the initiator's side.
//
// KEM flow (initiator side):
//  1. Receive the responder's HandshakeAnswer (contains PqcCiphertext).
//  2. Decapsulate using our own Kyber768 private key → recovers sharedSecret.
//  3. Feed sharedSecret into Handshake() — must match the responder's value.
func (of *Engine) FinishHandshake(answerBytes []byte) (string, error) {
	var answer Client.HandshakeAnswer
	if err := json.Unmarshal(answerBytes, &answer); err != nil {
		return "", fmt.Errorf("unmarshal answer: %w", err)
	}

	// FIX (critical): bind claimed SenderId to the actual identity keys.
	// Without this check, Handshake()'s signature verification is only
	// self-consistent (verifies the sig against whatever key the payload
	// itself supplies), so any attacker can forge an answer claiming to be
	// a known SenderId while using their own keys — full MITM / identity
	// spoofing. This check must mirror the one already present in AcceptOffer.
	derivedSenderId := crypto.DerivePeerID(answer.IdPub, answer.DilithiumPub)
	if derivedSenderId != answer.SenderId {
		return "", fmt.Errorf("sender ID spoofing detected in answer: id does not match identity public key")
	}

	peer, ok := of.Client.Sessions["pending_"+answer.SenderId]
	if !ok {
		peer, ok = of.Client.Sessions["pending"]
		if !ok {
			return "", fmt.Errorf("no pending session found for %s", answer.SenderId)
		}
	}

	if len(answer.KyberCiphertext) == 0 {
		return "", fmt.Errorf("answer missing PQC ciphertext")
	}

	scheme := kyber768.Scheme()

	kyberPriv, err := scheme.UnmarshalBinaryPrivateKey(peer.PqcPrivateKey)
	if err != nil {
		return "", fmt.Errorf("unmarshal kyber private key: %w", err)
	}

	sharedSecret, err := scheme.Decapsulate(kyberPriv, answer.KyberCiphertext)
	if err != nil {
		return "", fmt.Errorf("kyber decapsulate: %w", err)
	}

	myIdBytes, err := base58.Decode(of.Client.Id)
	if err != nil {
		return "", fmt.Errorf("decode client id: %w", err)
	}

	if err := peer.Handshake(
		answer.IdPub,
		answer.Pub,
		answer.DhPub,
		answer.KyberPub,
		answer.DilithiumPub,
		answer.Sign,
		answer.DilithiumSign,
		sharedSecret,
		answer.OfferID,
		myIdBytes,
	); err != nil {
		return "", fmt.Errorf("handshake (initiator): %w", err)
	}

	delete(of.Client.Sessions, "pending")
	delete(of.Client.Sessions, "pending_"+answer.SenderId)
	of.Client.Sessions[answer.SenderId] = peer
	Client.SaveClient(of.Client)

	return answer.SenderId, nil
}

// Encrypt (Step 4) - Wraps a message for a peer
func (of *Engine) Encrypt(peerID, message string) ([]byte, error) {
	session, ok := of.Client.Sessions[peerID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	cipher := session.Encrypt(of.Client.Id, []byte(message))
	Client.SaveClient(of.Client)

	return cipher, nil
}

// Decrypt (Step 5) - Decodes a Base64 message
func (of *Engine) Decrypt(payloadB64 string) (string, string, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", "", err
	}

	senderID, pt, err := of.Client.Decrypt(payloadBytes)
	if err != nil {
		return "", "", err
	}
	Client.SaveClient(of.Client)
	return senderID, string(pt), nil
}

func (of *Engine) Initialize() *Client.Client {
	of.Client = Client.NewClient()
	Client.SaveClient(of.Client)
	return of.Client
}

func (of *Engine) LoadClient(id string) (*Client.Client, error) {
	filename := fmt.Sprintf("%s.json", id)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cl Client.Client
	if err := json.Unmarshal(data, &cl); err != nil {
		return nil, err
	}
	of.Client = &cl
	return &cl, nil
}

func (of *Engine) SaveClient() {
	Client.SaveClient(of.Client)
}
