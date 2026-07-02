package offline

type AcceptResponse struct {
	Type     string `json:"type"`
	Envelope string `json:"envelope"`
}
type DecryptResponse struct {
	Sender  string `json:"sender"`
	Message string `json:"message"`
}
type EncryptResponse struct {
	Type     string `json:"type"`
	Envelope string `json:"envelope"`
}
type FinishResponse struct {
	PeerID string `json:"remotePeer"`
}
type InitResponse struct {
	ID string `json:"id"`
}
type OfferResponse struct {
	Type     string `json:"type"`
	Envelope string `json:"envelope"`
}

type AcceptRequest struct {
	ID            string `json:"id"`
	OfferEnvelope string `json:"offerEnvelope"`
}
type DecryptRequest struct {
	ID         string `json:"id"`
	CipherText string `json:"cipherText"`
}

type EncryptRequest struct {
	ID         string `json:"id"`
	RemotePeer string `json:"remotePeer"`
	Message    string `json:"message"`
}

type FinishRequest struct {
	ID             string `json:"id"`
	AnswerEnvelope string `json:"answerEnvelope"`
}
type OfferRequest struct {
	ID         string `json:"id"`
	RemotePeer string `json:"remotePeer"`
}
