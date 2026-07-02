package crypto

type HandshakeOffer struct {
	SenderId      string `json:"senderId"`
	RecipientId   []byte `json:"recipientId"`
	OfferID       []byte `json:"offerID"`
	IdPub         []byte `json:"idPub"`         // Ed25519 pub
	Pub           []byte `json:"pub"`           // X25519 pub
	DhPub         []byte `json:"dhPub"`         // ratchet DH pub
	KyberPub      []byte `json:"kyberPub"`      // Kyber768 pub
	DilithiumPub  []byte `json:"dilithiumPub"`  // Dilithium3 pub
	Sign          []byte `json:"sign"`          // Ed25519 signature
	DilithiumSign []byte `json:"dilithiumSign"` // ← Dilithium3 signature
}

type HandshakeAnswer struct {
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
	DilithiumSign   []byte `json:"dilithiumSign"` // ← جدید
}
type Response struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}
