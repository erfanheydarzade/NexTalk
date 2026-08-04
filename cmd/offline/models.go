package offline

type Envelope struct {
	Type string `bin:"0"`
	Data []byte `bin:"1"`
}

type InitResponse struct {
	ID string `bin:"0"`
}

type OfferResponse struct {
	RemotePeer string `bin:"0"`
	Envelope   string `bin:"1"`
	Encoding   string `bin:"2"`
}

type AcceptResponse struct {
	Envelope string `bin:"0"`
	Encoding string `bin:"1"`
}

type FinishResponse struct {
	PeerID string `bin:"0"`
}

type EncryptResponse struct {
	Type     string `bin:"0"`
	Envelope string `bin:"1"`
}

type DecryptResponse struct {
	Sender   string `bin:"0"`
	Encoding string `bin:"1"`
	Message  string `bin:"2"`
}

type AcceptRequest struct {
	ID            string `bin:"0"`
	OfferEnvelope string `bin:"1"`
}

type DecryptRequest struct {
	ID         string `bin:"0"`
	CipherText string `bin:"1"`
}

type EncryptRequest struct {
	ID         string `bin:"0"`
	RemotePeer string `bin:"1"`
	Message    string `bin:"2"`
}

type FinishRequest struct {
	ID             string `bin:"0"`
	AnswerEnvelope string `bin:"1"`
}

type OfferRequest struct {
	ID         string `bin:"0"`
	RemotePeer string `bin:"1"`
}
