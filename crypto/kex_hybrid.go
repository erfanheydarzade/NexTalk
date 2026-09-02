package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/erfanheydarzade/nanopack"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// ErrReplay marks frames rejected because their nonce predates the receive
// chain. Genuine replays are rare in practice — far more often this means
// the SENDER's session state was rolled back (e.g. two NexTalk processes
// sharing one identity, or a restored <id>.json), so they re-sent with
// nonces the receiver has already consumed. Callers should surface it as an
// actionable condition, not a security alarm.
var ErrReplay = errors.New("replay attack or message too old")

var lowSecurity = false

const maxSkip = 1000

// keyLabel returns a short hex prefix for easy visual identification.
func keyLabel(key []byte) string {
	if key == nil {
		return "<nil>"
	}
	return hex.EncodeToString(key[:4]) + "…"
}

// SecureMessage represents an encrypted transport unit in the system.
//
// The `bin:"N"` tags drive nanopack code generation (see
// kex_hybrid_nanopack.go, produced by `go run
// github.com/erfanheydarzade/nanopack/cmd/bingen`). Only the four
// authenticated fields carry tags, so the generated MarshalBinID emits
// exactly the tag-free canonical form the HMAC is computed over —
// secureMessageHmacPayload needs no nil-then-re-marshal tricks.
//
// Tag is deliberately untagged: it is appended to the wire frame after the
// canonical body under secureMessageFieldTag. RequestKey/AcceptedKey are
// handshake fields transported outside the ratchet frame and never travel
// in a SecureMessage.
//
//nanopack:schema id=1
type SecureMessage struct {
	SenderID   string `bin:"1"`
	RatchetKey []byte `bin:"2"`
	Nonce      uint64 `bin:"3"`
	Ciphertext []byte `bin:"4"`

	Tag         []byte
	RequestKey  []byte
	AcceptedKey []byte
}

// secureMessageFieldTag is the wire field ID of the HMAC tag. It continues
// the numbering of the generated SecureMessageField* constants and must not
// collide with them.
const secureMessageFieldTag uint8 = 5

// SecurePeer holds the full cryptographic state of a participant.
type SecurePeer struct {
	ExpectedPeerHash []byte `json:"expectedPeerHash"`

	IdentityPrivate ed25519.PrivateKey `json:"identityPrivate"`
	IdentityPublic  ed25519.PublicKey  `json:"identityPublic"`

	PqcSignPrivate []byte
	PqcSignPublic  []byte

	Private []byte `json:"private"`
	Public  []byte `json:"public"`

	PqcPrivateKey []byte `json:"pqcPrivateKey"`
	PqcPublicKey  []byte `json:"pqcPublicKey"`

	DhPrivate      []byte `json:"dhPrivate"`
	DhPublic       []byte `json:"dhPublic"`
	RemoteDhPublic []byte `json:"remoteDhPublic"`

	RootKey []byte `json:"rootKey"`
	SendCk  []byte `json:"sendCk"`
	RecvCk  []byte `json:"recvCk"`
	HmacKey []byte `json:"hmacKey"`
	FileKey []byte `json:"fileKey"`

	SendNonce int `json:"sendNonce"`
	RecvNonce int `json:"recvNonce"`

	SkippedMessages map[string][]byte `json:"skippedMessages"`

	AmInitiator bool `json:"amInitiator"`

	RemotePendingKey []byte `json:"remotePendingKey"`
	PubPendingKey    []byte `json:"pubPendingKey"`
	PrivPnedingKey   []byte `json:"privPnedingKey"`
	pendingDhRatchet bool

	SeenOffers map[string]bool `json:"seenOffers"`
}

func (sp *SecurePeer) PublicBytes() []byte {
	return sp.Public
}

func (sp *SecurePeer) IdentityPublicBytes() []byte {
	return sp.IdentityPublic
}

func (sp *SecurePeer) DhPubBytes() []byte {
	return sp.DhPublic
}

func (sp *SecurePeer) PqcPubBytes() []byte {
	return sp.PqcPublicKey
}

func GenerateDilithiumKeyPair() (privBytes []byte, pubBytes []byte) {
	scheme := mode3.Scheme()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		panic(err)
	}
	privB, _ := priv.MarshalBinary()
	pubB, _ := pub.MarshalBinary()
	return privB, pubB
}

func DilithiumSign(privBytes, message []byte) []byte {
	scheme := mode3.Scheme()
	priv, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
	if err != nil {
		panic(fmt.Sprintf("dilithium unmarshal private key: %v", err))
	}
	return scheme.Sign(priv, message, nil)
}

func DilithiumVerify(pubBytes, message, sig []byte) bool {
	scheme := mode3.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return false
	}
	return scheme.Verify(pub, message, sig, nil)
}

// DerivePeerID builds the canonical peer ID using Base58:
// base58( ed25519IdentityPublic + sha3_256(DilithiumPublicKey) )
func DerivePeerID(identityPublic, dilithiumPublic []byte) string {
	h := sha3.New256()
	h.Write(dilithiumPublic)
	dilHash := h.Sum(nil)

	// Explicit copy — NEVER `append(identityPublic, ...)`. Callers hand us
	// slices that alias larger buffers (e.g. nanopack-decoded wire frames,
	// where Data points into the payload); append would then write dilHash
	// through their spare capacity and corrupt whatever field follows.
	combined := make([]byte, 0, len(identityPublic)+len(dilHash))
	combined = append(combined, identityPublic...)
	combined = append(combined, dilHash...)
	return base58.Encode(combined)
}

// GetSign creates a classical Ed25519 signature over the peer's public identity material.
func (sp *SecurePeer) GetSign(offerID []byte, recipientID []byte) []byte {
	msg := sp.buildSignMessage(offerID, recipientID)
	return ed25519.Sign(sp.IdentityPrivate, msg)
}

// GetDilithiumSign returns the post-quantum Dilithium3 signature.
func (sp *SecurePeer) GetDilithiumSign(offerID []byte, recipientID []byte) []byte {
	msg := sp.buildSignMessage(offerID, recipientID)
	return DilithiumSign(sp.PqcSignPrivate, msg)
}

// buildSignMessage is the single source of truth for what gets signed.
func (sp *SecurePeer) buildSignMessage(offerID []byte, recipientID []byte) []byte {
	return bytes.Join([][]byte{
		recipientID,
		sp.PublicBytes(),
		sp.DhPubBytes(),
		sp.PqcPubBytes(),
		sp.PqcSignPublic,
		offerID,
	}, []byte{})
}

func GenerateOfferID() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// sortedByHash deterministically orders two byte arrays based on SHA-256 hash.
func (sp *SecurePeer) sortedByHash(a []byte, b []byte) ([]byte, []byte) {
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	if bytes.Compare(ha[:], hb[:]) < 0 {
		return a, b
	}
	return b, a
}

// logKeyEvent prints a debug-safe representation of key material.
func (sp *SecurePeer) logKeyEvent(event string, keys map[string][]byte) {
	parts := []string{fmt.Sprintf("[KEY] %s", event)}
	for name, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", name, keyLabel(key)))
	}
	fmt.Println(strings.Join(parts, " | "))
}

// getSkipKeyStr generates a deterministic lookup key for skipped message keys.
func (sp *SecurePeer) getSkipKeyStr(dh string, n int) string {
	return fmt.Sprintf("%s:%d", dh, n)
}

// GetTranscript builds a deterministic handshake transcript hash.
func (sp *SecurePeer) GetTranscript(peerIdentityBytes, peerPublicBytes, peerDhPublicBytes, peerPqcPublicBytes []byte) []byte {
	items := [][]byte{
		sp.IdentityPublicBytes(),
		sp.PublicBytes(),
		sp.DhPubBytes(),
		sp.PqcPubBytes(),
		peerIdentityBytes,
		peerPublicBytes,
		peerDhPublicBytes,
		peerPqcPublicBytes,
	}

	hashedItems := make([][]byte, len(items))
	for i, item := range items {
		h := sha3.New256()
		h.Write(item)
		hashedItems[i] = h.Sum(nil)
	}

	sort.Slice(hashedItems, func(i, j int) bool {
		return bytes.Compare(hashedItems[i], hashedItems[j]) < 0
	})

	hashBuilder := sha3.New512()
	hashBuilder.Write([]byte("ML-KEM-ECC-Hybrid-Transcript-v1"))
	for _, h := range hashedItems {
		hashBuilder.Write(h)
	}

	return hashBuilder.Sum(nil)
}

// Handshake performs hybrid key agreement (ECDH + PQC) and session setup.
//
// SECURITY NOTE: this function verifies that peerEd25519Sig/peerDilithiumSig
// are valid signatures BY peerIdentityBytes/peerDilithiumPublicBytes over msg.
// That check alone is self-consistent and does NOT prove peerIdentityBytes
// belongs to the SenderId the caller believes it's talking to. Callers
// (AcceptOffer, FinishHandshake) MUST independently verify
// DerivePeerID(peerIdentityBytes, peerDilithiumPublicBytes) == claimedSenderId
// before calling this, or before trusting the returned peer identity.
func (sp *SecurePeer) Handshake(
	peerIdentityBytes, peerPublicBytes, peerDhPublicBytes,
	peerKyberPublicBytes, peerDilithiumPublicBytes,
	peerEd25519Sig, peerDilithiumSig,
	pqcSharedSecret, offerID, recipientId []byte,
) error {

	// Reject malformed-length Ed25519 public keys before calling ed25519.Verify,
	// which panics (rather than returning false) on keys that aren't exactly
	// ed25519.PublicKeySize bytes. Without this, a tampered/truncated IdPub
	// field is a one-shot remote DoS.
	if len(peerIdentityBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("❌ invalid identity public key length: got %d, want %d",
			len(peerIdentityBytes), ed25519.PublicKeySize)
	}

	msg := bytes.Join([][]byte{
		recipientId,
		peerPublicBytes,
		peerDhPublicBytes,
		peerKyberPublicBytes,
		peerDilithiumPublicBytes,
		offerID,
	}, []byte{})

	// 1. Verify Ed25519 (classical).
	if !ed25519.Verify(peerIdentityBytes, msg, peerEd25519Sig) {
		return fmt.Errorf("❌ invalid Ed25519 signature")
	}

	// 2. Verify Dilithium3 (post-quantum) — both must pass.
	if !DilithiumVerify(peerDilithiumPublicBytes, msg, peerDilithiumSig) {
		return fmt.Errorf("❌ invalid Dilithium signature")
	}

	// 3. Verify ID binding (peer pinning), if pinned.
	//
	// ExpectedPeerHash stores the base58-encoded DerivePeerID string
	// (identity pub + sha3-256(dilithium pub)). We compare against the
	// correctly-derived expectedID; the old raw-bytes comparison was dead code.
	expectedID := DerivePeerID(peerIdentityBytes, peerDilithiumPublicBytes)
	if sp.ExpectedPeerHash != nil &&
		!bytes.Equal([]byte(expectedID), sp.ExpectedPeerHash) {
		return fmt.Errorf("❌ peer ID mismatch")
	}

	eccShared, err := curve25519.X25519(sp.Private, peerPublicBytes)
	if err != nil {
		return err
	}

	// Explicit copy — never append(eccShared, ...): eccShared may alias a
	// buffer with spare capacity (circl-returned slices are not guaranteed
	// exact-cap), and appending would write pqcSharedSecret through it.
	hybridSharedSecret := make([]byte, 0, len(eccShared)+len(pqcSharedSecret))
	hybridSharedSecret = append(hybridSharedSecret, eccShared...)
	hybridSharedSecret = append(hybridSharedSecret, pqcSharedSecret...)

	p1, _ := sp.sortedByHash(peerIdentityBytes, sp.IdentityPublicBytes())
	sp.AmInitiator = bytes.Equal(p1, sp.IdentityPublicBytes())

	transcript := sp.GetTranscript(peerIdentityBytes, peerPublicBytes, peerDhPublicBytes, peerKyberPublicBytes)

	hkdfReader := hkdf.New(sha256.New, hybridSharedSecret, transcript, []byte("initial-root"))
	rootMat := make([]byte, 32)
	io.ReadFull(hkdfReader, rootMat)
	sp.RootKey = rootMat

	sp.RemoteDhPublic = peerDhPublicBytes

	dhShared, _ := curve25519.X25519(sp.DhPrivate, sp.RemoteDhPublic)
	matReader := hkdf.New(sha256.New, dhShared, sp.RootKey, []byte("ratchet-root"))
	mat := make([]byte, 160)
	io.ReadFull(matReader, mat)

	if sp.AmInitiator {
		sp.SendCk = mat[0:32]
		sp.RecvCk = mat[32:64]
		sp.RootKey = mat[64:96]
		sp.HmacKey = mat[96:128]
		sp.FileKey = mat[128:160]
	} else {
		sp.RootKey = mat[64:96]
		sp.RecvCk = mat[0:32]
		sp.SendCk = mat[32:64]
		sp.HmacKey = mat[96:128]
		sp.FileKey = mat[128:160]
	}

	sp.SendNonce = 0
	sp.RecvNonce = 0

	if !sp.AmInitiator {
		sp.pendingDhRatchet = true
	}

	return nil
}

// SkipMessageKeys advances the receive ratchet up to a target message index.
func (sp *SecurePeer) SkipMessageKeys(untilMsgNumber int) error {
	if sp.RecvNonce+maxSkip < untilMsgNumber {
		return fmt.Errorf("too many skipped messages")
	}

	remoteDhStr := base64.StdEncoding.EncodeToString(sp.RemoteDhPublic)

	if sp.SkippedMessages == nil {
		sp.SkippedMessages = make(map[string][]byte)
	}

	for sp.RecvNonce < untilMsgNumber {
		nextCk, mk := RatchetStep(sp.RecvCk)
		sp.RecvCk = nextCk
		sp.SkippedMessages[sp.getSkipKeyStr(remoteDhStr, sp.RecvNonce)] = mk
		sp.RecvNonce++
	}
	return nil
}

// DhRatchet updates the receive-side Diffie-Hellman state.
func (sp *SecurePeer) DhRatchet(remoteKey []byte) {
	sp.RemoteDhPublic = remoteKey

	dhShared, _ := curve25519.X25519(sp.DhPrivate, sp.RemoteDhPublic)

	hkdfReader := hkdf.New(sha256.New, dhShared, sp.RootKey, []byte("ratchet-root"))
	material := make([]byte, 64)
	io.ReadFull(hkdfReader, material)

	sp.RootKey = material[:32]
	sp.RecvCk = material[32:]
	sp.RecvNonce = 0

	sp.pendingDhRatchet = true
}

// maxWireNonce bounds a nonce read off the wire before it is narrowed to
// the int used by the ratchet counters, so a hostile 64-bit value can never
// wrap negative on a 32-bit build.
const maxWireNonce = uint64(1) << 31

// secureMessageHmacPayload encodes the tag-free canonical form used for HMAC
// computation. It is exactly the generated MarshalBinID output — field IDs and
// their order are part of the wire contract, so do not reorder the tagged
// fields in SecureMessage. Tag, RequestKey and AcceptedKey are excluded:
// the tag authenticates this payload, and the two key fields are handshake
// material transported outside the ratchet frame.
func secureMessageHmacPayload(msg *SecureMessage) ([]byte, error) {
	return nanopack.MarshalFastID(msg)
}

// parseSecureMessage decodes a wire frame produced by Encrypt back into a
// SecureMessage. The four authenticated fields are handled by the generated
// UnmarshalBinID; the tag is read separately since it is deliberately outside
// the canonical HMAC payload.
func parseSecureMessage(payloadBytes []byte) (*SecureMessage, error) {
	fields, err := nanopack.DecodeID(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing message frame: %w", err)
	}

	var msg SecureMessage
	if err := msg.UnmarshalBinID(fields); err != nil {
		return nil, fmt.Errorf("error parsing message frame: %w", err)
	}
	for _, f := range fields {
		if f.ID == secureMessageFieldTag {
			msg.Tag = f.Data
		}
	}

	if msg.Nonce >= maxWireNonce {
		return nil, fmt.Errorf("nonce %d out of range", msg.Nonce)
	}
	return &msg, nil
}

// SenderIDFromFrame reads just the sender ID out of a wire frame, without
// verifying it. Callers use it to pick which session should attempt the
// decrypt; the sender is only trustworthy once Decrypt validates the HMAC
// under that session's key.
func SenderIDFromFrame(payloadBytes []byte) (string, error) {
	msg, err := parseSecureMessage(payloadBytes)
	if err != nil {
		return "", err
	}
	return msg.SenderID, nil
}

// Encrypt produces an authenticated encrypted message using the send ratchet.
func (sp *SecurePeer) Encrypt(senderName string, plaintext []byte) ([]byte, error) {
	var mk []byte
	var currentDhPublic []byte

	if !lowSecurity {
		if sp.pendingDhRatchet {
			sp.DhPrivate, sp.DhPublic = GenerateX25519KeyPair()

			dhShared, _ := curve25519.X25519(sp.DhPrivate, sp.RemoteDhPublic)
			hkdfReader := hkdf.New(sha256.New, dhShared, sp.RootKey, []byte("ratchet-root"))
			material := make([]byte, 64)
			io.ReadFull(hkdfReader, material)

			sp.RootKey = material[:32]
			sp.SendCk = material[32:]
			sp.SendNonce = 0

			sp.pendingDhRatchet = false
		}

		var nextCk []byte
		nextCk, mk = RatchetStep(sp.SendCk)
		sp.SendCk = nextCk
		currentDhPublic = sp.DhPublic

	} else {
		info := IntToBytes(sp.SendNonce, 8)
		h := hkdf.Expand(sha256.New, sp.SendCk, info)
		mk = make([]byte, 32)
		io.ReadFull(h, mk)
		currentDhPublic = sp.DhPublic
	}

	cipher, err := chacha20poly1305.NewX(mk)
	if err != nil {
		return nil, err
	}
	nonce := IntToBytes(sp.SendNonce, 24)
	aad := make([]byte, 0, len(currentDhPublic)+8)
	aad = append(aad, currentDhPublic...)
	aad = append(aad, IntToBytes(sp.SendNonce, 8)...)

	ciphertext := cipher.Seal(nil, nonce, plaintext, aad)

	msg := SecureMessage{
		SenderID:   senderName,
		RatchetKey: currentDhPublic,
		Nonce:      uint64(sp.SendNonce),
		Ciphertext: ciphertext,
	}

	// Compute HMAC over the tag-free canonical payload.
	canonical, err := secureMessageHmacPayload(&msg)
	if err != nil {
		return nil, fmt.Errorf("encoding canonical payload: %w", err)
	}
	mac := hmac.New(sha3.New256, sp.HmacKey)
	mac.Write(canonical)
	msg.Tag = mac.Sum(nil)

	// Wire frame: same fields as canonical + tag appended last.
	var enc nanopack.Encoder
	if err := msg.MarshalBinID(&enc); err != nil {
		return nil, fmt.Errorf("encoding message frame: %w", err)
	}
	enc.AddID(secureMessageFieldTag, msg.Tag)
	wire, err := enc.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding message frame: %w", err)
	}

	sp.SendNonce++
	return wire, nil
}

func (sp *SecurePeer) VerifyCiphertext(mk []byte, n int, ciphertext []byte, dhPub []byte) bool {
	cipher, err := chacha20poly1305.NewX(mk)
	if err != nil {
		return false
	}

	nonceBytes := IntToBytes(n, 24)
	aad := make([]byte, 0, len(dhPub)+8)
	aad = append(aad, dhPub...)
	aad = append(aad, IntToBytes(n, 8)...)

	aadCopy := make([]byte, len(aad))
	copy(aadCopy, aad)

	_, err = cipher.Open(nil, nonceBytes, ciphertext, aadCopy)
	return err == nil
}

// Decrypt validates and decrypts an incoming SecureMessage.
// Returns (senderID, plaintext, error).
func (sp *SecurePeer) Decrypt(payloadBytes []byte) (string, []byte, error) {
	msg, err := parseSecureMessage(payloadBytes)
	if err != nil {
		return "", nil, err
	}

	// Verify HMAC over the tag-free canonical form.
	canonical, err := secureMessageHmacPayload(msg)
	if err != nil {
		return "", nil, fmt.Errorf("encoding canonical payload: %w", err)
	}
	mac := hmac.New(sha3.New256, sp.HmacKey)
	mac.Write(canonical)
	calculatedTag := mac.Sum(nil)

	if !hmac.Equal(msg.Tag, calculatedTag) {
		return "", nil, fmt.Errorf("invalid authentication tag ❌")
	}

	// The ratchet counters are ints; msg.Nonce was already bounded by
	// parseSecureMessage so this narrowing cannot go negative.
	nonce := int(msg.Nonce)

	if lowSecurity {
		info := IntToBytes(nonce, 8)
		h := hkdf.Expand(sha256.New, sp.RecvCk, info)
		mk := make([]byte, 32)
		io.ReadFull(h, mk)

		plaintext, err := sp.DecryptWithKey(mk, nonce, msg.Ciphertext, msg.RatchetKey)
		return msg.SenderID, plaintext, err
	}

	// Check skipped-message cache first.
	skipKeyStr := sp.getSkipKeyStr(base64.StdEncoding.EncodeToString(msg.RatchetKey), nonce)
	if mk, exists := sp.SkippedMessages[skipKeyStr]; exists {
		delete(sp.SkippedMessages, skipKeyStr)
		plaintext, err := sp.DecryptWithKey(mk, nonce, msg.Ciphertext, msg.RatchetKey)
		return msg.SenderID, plaintext, err
	}

	// DH ratchet step if the sender has rotated their key.
	if sp.RemoteDhPublic == nil || !bytes.Equal(msg.RatchetKey, sp.RemoteDhPublic) {
		if sp.SkippedMessages == nil {
			sp.SkippedMessages = make(map[string][]byte)
		}
		sp.DhRatchet(msg.RatchetKey)
	}

	// Reject replays / messages from a past epoch.
	if nonce < sp.RecvNonce {
		return "", nil, fmt.Errorf("%w (N=%d, expected >= %d)",
			ErrReplay, nonce, sp.RecvNonce)
	}

	// Advance chain key, stashing keys for any gaps (out-of-order delivery).
	for sp.RecvNonce < nonce {
		nextCk, mk := RatchetStep(sp.RecvCk)
		sp.RecvCk = nextCk
		keyStr := sp.getSkipKeyStr(base64.StdEncoding.EncodeToString(sp.RemoteDhPublic), sp.RecvNonce)
		if sp.SkippedMessages == nil {
			sp.SkippedMessages = make(map[string][]byte)
		}
		sp.SkippedMessages[keyStr] = mk
		sp.RecvNonce++
	}

	nextCk, mk := RatchetStep(sp.RecvCk)
	sp.RecvCk = nextCk
	sp.RecvNonce++

	plaintext, err := sp.DecryptWithKey(mk, nonce, msg.Ciphertext, msg.RatchetKey)
	return msg.SenderID, plaintext, err
}

// DecryptWithKey performs AEAD decryption using a derived message key.
func (sp *SecurePeer) DecryptWithKey(mk []byte, n int, ciphertext []byte, dhPub []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.NewX(mk)
	if err != nil {
		return nil, err
	}

	nonceBytes := IntToBytes(n, 24)

	aad := make([]byte, 0, len(dhPub)+8)
	aad = append(aad, dhPub...)
	aad = append(aad, IntToBytes(n, 8)...)

	plaintext, err := cipher.Open(nil, nonceBytes, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("ciphertext tampered or invalid AEAD")
	}

	return plaintext, nil
}
