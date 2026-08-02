package core

// HandShakeOffer is the wire type for Step 1 of the NexTalk key-agreement protocol.
type HandShakeOffer struct {
	SenderId      string `bin:"senderId" json:"senderId"`
	RecipientId   []byte `bin:"recipientId" json:"recipientId"`
	OfferID       []byte `bin:"offerID" json:"offerID"`
	IdPub         []byte `bin:"idPub" json:"idPub"`               // Ed25519 identity pub
	Pub           []byte `bin:"pub" json:"pub"`                   // X25519 ephemeral pub
	DhPub         []byte `bin:"dhPub" json:"dhPub"`               // Ratchet DH pub
	KyberPub      []byte `bin:"kyberPub" json:"kyberPub"`         // Kyber768 KEM pub
	DilithiumPub  []byte `bin:"dilithiumPub" json:"dilithiumPub"` // Dilithium3 signing pub
	Sign          []byte `bin:"sign" json:"sign"`                 // Ed25519 signature
	DilithiumSign []byte `bin:"dilithiumSign" json:"dilithiumSign"`
}

// HandShakeAnswer is the wire type for Step 2 (responder → initiator).
type HandShakeAnswer struct {
	SenderId        string `bin:"senderId" json:"senderId"`
	RecipientId     []byte `bin:"recipientId" json:"recipientId"`
	OfferID         []byte `bin:"offerID" json:"offerID"`
	IdPub           []byte `bin:"idPub" json:"idPub"`
	Pub             []byte `bin:"pub" json:"pub"`
	DhPub           []byte `bin:"dhPub" json:"dhPub"`
	KyberPub        []byte `bin:"kyberPub" json:"kyberPub"`
	KyberCiphertext []byte `bin:"kyberCiphertext" json:"kyberCiphertext"`
	DilithiumPub    []byte `bin:"dilithiumPub" json:"dilithiumPub"`
	Sign            []byte `bin:"sign" json:"sign"`
	DilithiumSign   []byte `bin:"dilithiumSign" json:"dilithiumSign"`
}

// Response is the standard envelope used by cmd-layer handlers.
type Response struct {
	Status  string      `bin:"status" json:"status"`
	Data    interface{} `bin:"data" json:"data,omitempty"`
	Message string      `bin:"message" json:"message,omitempty"`
}
