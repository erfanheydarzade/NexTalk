package worker

type InitResponse struct {
	ID string `json:"id"`
}

type ConnectResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EncryptResponse struct {
	Peer string `json:"peer"`
}
type ListenResponse struct {
	Events []ListenEvent `json:"events"`
}

type ListenEvent struct {
	Type    string         `json:"type"`
	Actions []ListenAction `json:"actions,omitempty"`

	Sender  string `json:"sender,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Message string `json:"message,omitempty"`
}

type ListenAction struct {
	Type string `json:"type"`

	Peer string `json:"peer,omitempty"`
}
