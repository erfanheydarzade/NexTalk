package core

// The handshake types below are JSON on the wire (see engine.go's
// json.Marshal/Unmarshal calls). They carry no `bin:"N"` tags, so
// nanopack's bingen skips them; the `json:"..."` tags are the contract.

// HandShakeOffer is the wire type for Step 1 of the NexTalk key-agreement protocol.
type HandShakeOffer struct {
	SenderId      string `json:"senderId"`
	RecipientId   []byte `json:"recipientId"`
	OfferID       []byte `json:"offerID"`
	IdPub         []byte `json:"idPub"`
	Pub           []byte `json:"pub"`
	DhPub         []byte `json:"dhPub"`
	KyberPub      []byte `json:"kyberPub"`
	DilithiumPub  []byte `json:"dilithiumPub"`
	Sign          []byte `json:"sign"`
	DilithiumSign []byte `json:"dilithiumSign"`
}

// HandShakeAnswer is the wire type for Step 2 (responder → initiator).
type HandShakeAnswer struct {
	SenderId        string `json:"senderId"`
	RecipientId     []byte `json:"recipientId"`
	OfferID         []byte `json:"offerID"`
	IdPub           []byte `json:"idPub"`
	Pub             []byte `json:"pub"`
	DhPub           []byte `json:"dhPub"`
	KyberPub        []byte `json:"kyberPub"`
	KyberCiphertext []byte `json:"kyberCiphertext"`
	DilithiumPub    []byte `json:"dilithiumPub"`
	Sign            []byte `json:"sign"`
	DilithiumSign   []byte `json:"dilithiumSign"`
}

// Response is the standard envelope used by cmd-layer handlers.
type Response struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}
