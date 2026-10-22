package ntxhost

import (
	"fmt"

	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// This file holds the pieces of WASM ABI v1 (see internal/transport/wasm.go)
// that are pure data handling, so the JS-side host and the wazero host share
// ONE definition of them and both are testable natively.

// ParsePollBlob splits an ntx_poll result: a run of BE32-length-prefixed
// full frames ("empty blob when none").
func ParsePollBlob(blob []byte) ([][]byte, error) {
	var out [][]byte
	for pos := 0; pos < len(blob); {
		if pos+4 > len(blob) {
			return nil, &transport.RPCError{Code: transport.ErrTransport, Detail: "poll blob truncated"}
		}
		n := int(uint32(blob[pos])<<24 | uint32(blob[pos+1])<<16 | uint32(blob[pos+2])<<8 | uint32(blob[pos+3]))
		pos += 4
		if n <= 0 || n > transport.MaxFrameBytes || pos+n > len(blob) {
			return nil, &transport.RPCError{Code: transport.ErrTransport, Detail: "poll frame out of bounds"}
		}
		out = append(out, append([]byte(nil), blob[pos:pos+n]...))
		pos += n
	}
	return out, nil
}

// MaxPollBlob mirrors the wazero host's blob ceiling (32 frames of max size
// plus their 4-byte prefixes, with slack).
const MaxPollBlob = transport.MaxFrameBytes*33 + 16

// ABIError maps an ABI return code of op ("send", "attach", "detach",
// "start", "stop") to the same errors the wazero host produces.
func ABIError(op string, rc int) error {
	if rc == 0 {
		return nil
	}
	switch op {
	case "send":
		switch rc {
		case 1:
			return &transport.RPCError{Code: transport.ErrNotReady, Detail: "transport not started"}
		case 3:
			return &transport.RPCError{Code: transport.ErrTransport, Detail: "transport queue full"}
		}
		return &transport.RPCError{Code: transport.ErrTransport, Detail: fmt.Sprintf("send refused: %d", rc)}
	case "attach", "detach":
		return &transport.RPCError{Code: transport.ErrTransport, Detail: fmt.Sprintf("%s refused: %d", op, rc)}
	}
	return fmt.Errorf("transport: wasm %s refused: %d", op, rc)
}
