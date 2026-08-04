package core

// HandShakeOffer is the wire type for Step 1 of the NexTalk key-agreement protocol.
type HandShakeOffer struct {
	SenderId      string `bin:"0" json:"senderId"`
	RecipientId   []byte `bin:"1" json:"recipientId"`
	OfferID       []byte `bin:"2" json:"offerID"`
	IdPub         []byte `bin:"3" json:"idPub"`
	Pub           []byte `bin:"4" json:"pub"`
	DhPub         []byte `bin:"5" json:"dhPub"`
	KyberPub      []byte `bin:"6" json:"kyberPub"`
	DilithiumPub  []byte `bin:"7" json:"dilithiumPub"`
	Sign          []byte `bin:"8" json:"sign"`
	DilithiumSign []byte `bin:"9" json:"dilithiumSign"`
}

// HandShakeAnswer is the wire type for Step 2 (responder → initiator).
type HandShakeAnswer struct {
	SenderId        string `bin:"0" json:"senderId"`
	RecipientId     []byte `bin:"1" json:"recipientId"`
	OfferID         []byte `bin:"2" json:"offerID"`
	IdPub           []byte `bin:"3" json:"idPub"`
	Pub             []byte `bin:"4" json:"pub"`
	DhPub           []byte `bin:"5" json:"dhPub"`
	KyberPub        []byte `bin:"6" json:"kyberPub"`
	KyberCiphertext []byte `bin:"7" json:"kyberCiphertext"`
	DilithiumPub    []byte `bin:"8" json:"dilithiumPub"`
	Sign            []byte `bin:"9" json:"sign"`
	DilithiumSign   []byte `bin:"10" json:"dilithiumSign"`
}

// Response is the standard envelope used by cmd-layer handlers.
type Response struct {
	Status  string      `bin:"0" json:"status"`
	Data    interface{} `bin:"1" json:"data,omitempty"`
	Message string      `bin:"2" json:"message,omitempty"`
}
