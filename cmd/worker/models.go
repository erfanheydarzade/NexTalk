package worker

type InitResponse struct {
	ID string `json:"id"`
}

type ConnectResponse struct {
	Success bool   `json:"success"`
	Peer    string `json:"peer,omitempty"`
	Message string `json:"message"`
}

type EncryptResponse struct {
	Peer     string `json:"peer"`
	Encoding string `json:"encoding,omitempty"`
	Message  string `json:"message,omitempty"`
}

type ListenResponse struct {
	Events []ListenEvent `json:"events"`
}

type ListenEvent struct {
	Type     string         `json:"type"`
	Peer     string         `json:"peer,omitempty"`
	Sender   string         `json:"sender,omitempty"`
	Encoding string         `json:"encoding,omitempty"`
	Message  string         `json:"message,omitempty"`
	Context  string         `json:"context,omitempty"`
	Actions  []ListenAction `json:"actions,omitempty"`
}

type ListenAction struct {
	Type string `json:"type"`
	Peer string `json:"peer,omitempty"`
}
