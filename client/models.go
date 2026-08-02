package client

// HandshakeOffer and HandshakeAnswer have been moved to the core package as
// unexported types (handshakeOffer / handshakeAnswer).  They are internal
// protocol details of the Engine and should never be needed by callers
// outside core — all public APIs consume/produce raw JSON bytes.
//
// Response is kept here because it is used by cmd-layer handlers that already
// import the client package.  If you prefer, move it to core.Response.

// Response is the standard envelope returned by cmd-layer handlers.
type Response struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}
