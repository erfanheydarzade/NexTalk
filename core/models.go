package core

import (
	"encoding/json"
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

// The handshake types below are nanopack on the wire (compact binary,
// 1-byte field IDs — see https://github.com/erfanheydarzade/nanopack).
// The `json:"..."` tags remain only so the LEGACY JSON encoding can still
// be READ: peers running older builds send JSON offers/answers, and
// decodeOffer/decodeAnswer accept both. Everything we SEND is nanopack.
//
// A nanopack payload always starts with its field count (≤ 11 here), never
// the byte '{' (0x7B) that every JSON object starts with — that is the
// discriminator used by the decode helpers below.

// Field IDs (bin tags) are permanent once shipped — see nanopack's
// wire-compatibility notes before renumbering anything.

// HandShakeOffer is the wire type for Step 1 of the NexTalk key-agreement protocol.
//
//nanopack:schema id=20
type HandShakeOffer struct {
	SenderId      string `bin:"1" json:"senderId"`
	RecipientId   []byte `bin:"2" json:"recipientId"`
	OfferID       []byte `bin:"3" json:"offerID"`
	IdPub         []byte `bin:"4" json:"idPub"`
	Pub           []byte `bin:"5" json:"pub"`
	DhPub         []byte `bin:"6" json:"dhPub"`
	KyberPub      []byte `bin:"7" json:"kyberPub"`
	DilithiumPub  []byte `bin:"8" json:"dilithiumPub"`
	Sign          []byte `bin:"9" json:"sign"`
	DilithiumSign []byte `bin:"10" json:"dilithiumSign"`
}

// MarshalBinID implements nanopack.BinMarshalerID.
func (o *HandShakeOffer) MarshalBinID(e *nanopack.Encoder) error {
	e.AddID(1, []byte(o.SenderId))
	e.AddID(2, o.RecipientId)
	e.AddID(3, o.OfferID)
	e.AddID(4, o.IdPub)
	e.AddID(5, o.Pub)
	e.AddID(6, o.DhPub)
	e.AddID(7, o.KyberPub)
	e.AddID(8, o.DilithiumPub)
	e.AddID(9, o.Sign)
	e.AddID(10, o.DilithiumSign)
	return nil
}

// UnmarshalBinID implements nanopack.BinUnmarshalerID.
func (o *HandShakeOffer) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case 1:
			o.SenderId = string(f.Data)
		case 2:
			o.RecipientId = f.Data
		case 3:
			o.OfferID = f.Data
		case 4:
			o.IdPub = f.Data
		case 5:
			o.Pub = f.Data
		case 6:
			o.DhPub = f.Data
		case 7:
			o.KyberPub = f.Data
		case 8:
			o.DilithiumPub = f.Data
		case 9:
			o.Sign = f.Data
		case 10:
			o.DilithiumSign = f.Data
		}
	}
	return nil
}

// HandShakeAnswer is the wire type for Step 2 (responder → initiator).
//
//nanopack:schema id=21
type HandShakeAnswer struct {
	SenderId        string `bin:"1" json:"senderId"`
	RecipientId     []byte `bin:"2" json:"recipientId"`
	OfferID         []byte `bin:"3" json:"offerID"`
	IdPub           []byte `bin:"4" json:"idPub"`
	Pub             []byte `bin:"5" json:"pub"`
	DhPub           []byte `bin:"6" json:"dhPub"`
	KyberPub        []byte `bin:"7" json:"kyberPub"`
	KyberCiphertext []byte `bin:"8" json:"kyberCiphertext"`
	DilithiumPub    []byte `bin:"9" json:"dilithiumPub"`
	Sign            []byte `bin:"10" json:"sign"`
	DilithiumSign   []byte `bin:"11" json:"dilithiumSign"`
}

// MarshalBinID implements nanopack.BinMarshalerID.
func (a *HandShakeAnswer) MarshalBinID(e *nanopack.Encoder) error {
	e.AddID(1, []byte(a.SenderId))
	e.AddID(2, a.RecipientId)
	e.AddID(3, a.OfferID)
	e.AddID(4, a.IdPub)
	e.AddID(5, a.Pub)
	e.AddID(6, a.DhPub)
	e.AddID(7, a.KyberPub)
	e.AddID(8, a.KyberCiphertext)
	e.AddID(9, a.DilithiumPub)
	e.AddID(10, a.Sign)
	e.AddID(11, a.DilithiumSign)
	return nil
}

// UnmarshalBinID implements nanopack.BinUnmarshalerID.
func (a *HandShakeAnswer) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case 1:
			a.SenderId = string(f.Data)
		case 2:
			a.RecipientId = f.Data
		case 3:
			a.OfferID = f.Data
		case 4:
			a.IdPub = f.Data
		case 5:
			a.Pub = f.Data
		case 6:
			a.DhPub = f.Data
		case 7:
			a.KyberPub = f.Data
		case 8:
			a.KyberCiphertext = f.Data
		case 9:
			a.DilithiumPub = f.Data
		case 10:
			a.Sign = f.Data
		case 11:
			a.DilithiumSign = f.Data
		}
	}
	return nil
}

// ── Dual-format decoding ─────────────────────────────────────────────────────

// cloneField copies a decoded field into a fresh buffer. nanopack's FieldID
// documents that Data ALIASES the input payload; since handshake structs are
// retained (pending sessions, SeenOffers keys, transcript hashing) and the
// payload is caller-owned scratch, every binary decode clones. The cost is
// trivial next to Kyber/Dilithium arithmetic.
func cloneField(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// cloneAll deep-copies every byte-slice field of an offer in place.
func (o *HandShakeOffer) cloneAll() {
	o.RecipientId = cloneField(o.RecipientId)
	o.OfferID = cloneField(o.OfferID)
	o.IdPub = cloneField(o.IdPub)
	o.Pub = cloneField(o.Pub)
	o.DhPub = cloneField(o.DhPub)
	o.KyberPub = cloneField(o.KyberPub)
	o.DilithiumPub = cloneField(o.DilithiumPub)
	o.Sign = cloneField(o.Sign)
	o.DilithiumSign = cloneField(o.DilithiumSign)
}

// cloneAll deep-copies every byte-slice field of an answer in place.
func (a *HandShakeAnswer) cloneAll() {
	a.RecipientId = cloneField(a.RecipientId)
	a.OfferID = cloneField(a.OfferID)
	a.IdPub = cloneField(a.IdPub)
	a.Pub = cloneField(a.Pub)
	a.DhPub = cloneField(a.DhPub)
	a.KyberPub = cloneField(a.KyberPub)
	a.KyberCiphertext = cloneField(a.KyberCiphertext)
	a.DilithiumPub = cloneField(a.DilithiumPub)
	a.Sign = cloneField(a.Sign)
	a.DilithiumSign = cloneField(a.DilithiumSign)
}

// DecodeOffer parses offer wire bytes in either encoding: current nanopack
// binary or the legacy JSON produced by older builds. Exported so transport
// dispatch layers (which need offer metadata before/instead of running the
// handshake) share exactly one decoder with Engine.AcceptOffer.
func DecodeOffer(b []byte) (*HandShakeOffer, error) {
	return decodeOffer(b)
}

// decodeOffer parses offer wire bytes in either encoding: current nanopack
// binary or the legacy JSON produced by older builds.
func decodeOffer(b []byte) (*HandShakeOffer, error) {
	var offer HandShakeOffer
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &offer); err != nil {
			return nil, fmt.Errorf("legacy json offer: %w", err)
		}
		return &offer, nil // encoding/json already copies byte fields
	}
	if err := nanopack.UnmarshalFastID(b, &offer); err != nil {
		return nil, fmt.Errorf("nanopack offer: %w", err)
	}
	offer.cloneAll()
	return &offer, nil
}

// DecodeAnswer parses answer wire bytes in either encoding. Exported for
// transport dispatch layers, mirroring DecodeOffer.
func DecodeAnswer(b []byte) (*HandShakeAnswer, error) {
	return decodeAnswer(b)
}

// decodeAnswer parses answer wire bytes in either encoding.
func decodeAnswer(b []byte) (*HandShakeAnswer, error) {
	var answer HandShakeAnswer
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &answer); err != nil {
			return nil, fmt.Errorf("legacy json answer: %w", err)
		}
		return &answer, nil
	}
	if err := nanopack.UnmarshalFastID(b, &answer); err != nil {
		return nil, fmt.Errorf("nanopack answer: %w", err)
	}
	answer.cloneAll()
	return &answer, nil
}

// PeekAnswerSenderID extracts the answer's SenderId without any crypto or
// session work. Used by client.FinishHandshake to locate the pending peer
// before completing the handshake. Accepts both wire encodings.
func PeekAnswerSenderID(answerBytes []byte) (string, error) {
	answer, err := decodeAnswer(answerBytes)
	if err != nil {
		return "", err
	}
	return answer.SenderId, nil
}

// Response is the standard envelope used by cmd-layer handlers. It exists
// ONLY at the scripting boundary (`--format json` CLI output) — it never
// travels over the wire.
type Response struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}
