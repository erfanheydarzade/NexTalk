package offline

// Envelope wraps handshake payloads for transport.
// Data is raw binary — the binary encoder handles []byte natively, no base64.
type Envelope struct {
	Type string `bin:"type"`
	Data []byte `bin:"data"`
}

type InitResponse struct {
	ID string `bin:"id"`
}

// OfferResponse mirrors DecryptResponse's shape: RemotePeer identifies who
// the offer is for, Envelope carries either the encoded envelope or (when
// --output was used) the path it was saved to, and Encoding says which.
type OfferResponse struct {
	RemotePeer string `bin:"remotePeer"`
	Envelope   string `bin:"envelope"`
	Encoding   string `bin:"encoding"`
}

// AcceptResponse carries the generated answer envelope, or the file path it
// was saved to, matching OfferResponse/DecryptResponse's Encoding field.
type AcceptResponse struct {
	Envelope string `bin:"envelope"`
	Encoding string `bin:"encoding"`
}

type FinishResponse struct {
	PeerID string `bin:"remotePeer"`
}

type EncryptResponse struct {
	Type     string `bin:"type"`
	Envelope string `bin:"envelope"`
}

type DecryptResponse struct {
	Sender   string `bin:"sender"`
	Encoding string `bin:"encoding"`
	Message  string `bin:"message"`
}

type AcceptRequest struct {
	ID            string `bin:"id"`
	OfferEnvelope string `bin:"offerEnvelope"`
}

type DecryptRequest struct {
	ID         string `bin:"id"`
	CipherText string `bin:"cipherText"`
}

type EncryptRequest struct {
	ID         string `bin:"id"`
	RemotePeer string `bin:"remotePeer"`
	Message    string `bin:"message"`
}

type FinishRequest struct {
	ID             string `bin:"id"`
	AnswerEnvelope string `bin:"answerEnvelope"`
}

type OfferRequest struct {
	ID         string `bin:"id"`
	RemotePeer string `bin:"remotePeer"`
}
