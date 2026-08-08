package offline

// The types below are the CLI's own request/response shapes, not wire
// packets: they are marshalled with encoding/json for `--format json`.
// They deliberately carry no `bin:"N"` tags, so nanopack's bingen skips
// them — only crypto.SecureMessage is a real nanopack packet.
//
// Since they have no `json:"..."` tags either, the JSON keys are the
// exported Go field names (ID, Envelope, Sender, ...). Programmatic
// consumers depend on that casing.

type Envelope struct {
	Type string
	Data []byte
}

type InitResponse struct {
	ID string
}

type OfferResponse struct {
	RemotePeer string
	Envelope   string
	Encoding   string
}

type AcceptResponse struct {
	Envelope string
	Encoding string
}

type FinishResponse struct {
	PeerID string
}

type EncryptResponse struct {
	Type     string
	Envelope string
}

type DecryptResponse struct {
	Sender   string
	Encoding string
	Message  string
}

type AcceptRequest struct {
	ID            string
	OfferEnvelope string
}

type DecryptRequest struct {
	ID         string
	CipherText string
}

type EncryptRequest struct {
	ID         string
	RemotePeer string
	Message    string
}

type FinishRequest struct {
	ID             string
	AnswerEnvelope string
}

type OfferRequest struct {
	ID         string
	RemotePeer string
}
