package transport

import (
	"encoding/binary"
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

// RPC schema IDs (100–126). No collision with NexTalk core schemas
// (1,10,11,20,21,40,41,44) or FileRelay (50–77).
const (
	SchemaEnvelope   byte = 100
	SchemaInitialize byte = 101
	SchemaInitResult byte = 102
	SchemaSend       byte = 103
	SchemaAck        byte = 104
	SchemaAttach     byte = 105
	SchemaDetach     byte = 106
	SchemaPoll       byte = 107
	SchemaPollResult byte = 108
	SchemaStatusReq  byte = 109
	SchemaStatus     byte = 110
	SchemaCapsReq    byte = 111
	SchemaCaps       byte = 112
	SchemaError      byte = 113
	SchemaStartStop  byte = 114

	// binary-transfer capability (additive; message-only transports
	// answer these with op-0 errors or never see them — see FileRoute).
	SchemaXferCreate   byte = 115
	SchemaXferCreated  byte = 116
	SchemaXferPut      byte = 117
	SchemaXferProgress byte = 118
	SchemaXferResume   byte = 119
	SchemaXferGet      byte = 120
	SchemaXferChunk    byte = 121
	SchemaXferComplete byte = 122
	SchemaXferCancel   byte = 127

	// Mailbox management for courier-model transports (scoped credentials
	// stay transport-side; core only ever sees mailbox bearers).
	SchemaRegister       byte = 123
	SchemaRegisterResult byte = 124
	SchemaResolve        byte = 125
	SchemaResolveResult  byte = 126
)

// OpError is the envelope op for failures: payload is SchemaError.
// Any op may answer with OpError instead of its typed response.
const OpError uint8 = 0

// Ops carried in Envelope.Op.
const (
	OpInitialize   uint8 = 1
	OpStartStop    uint8 = 2
	OpSend         uint8 = 3
	OpAttach       uint8 = 4
	OpDetach       uint8 = 5
	OpPoll         uint8 = 6
	OpStatus       uint8 = 7
	OpCapabilities uint8 = 8

	OpRegister     uint8 = 9
	OpResolve      uint8 = 10
	OpXferCreate   uint8 = 11
	OpXferPut      uint8 = 12
	OpXferResume   uint8 = 13
	OpXferGet      uint8 = 14
	OpXferComplete uint8 = 15
	OpXferCancel   uint8 = 16
)

// StartStop actions.
const (
	ActionStart uint8 = 1
	ActionStop  uint8 = 2
)

// Error codes for SchemaError.
const (
	ErrInvalid      uint32 = 1
	ErrUnsupported  uint32 = 2
	ErrNotReady     uint32 = 3
	ErrTransport    uint32 = 4
	ErrUnauthorized uint32 = 5
)

// MaxFrameBytes bounds one opaque core frame on the RPC (type byte +
// SecureMessage nanopack). Matches the 32 KiB message ceiling + headroom.
const MaxFrameBytes = 40 * 1024

// MaxRPCBytes bounds a single framed RPC body.
const MaxRPCBytes = 2 << 20

// Envelope multiplexes ops over one stdio stream: FID 1=op u8, 2=req_id u32 BE, 3=payload bytes.
type Envelope struct {
	Op      uint8
	ReqID   uint32
	Payload []byte
}

// MarshalEnvelope encodes an envelope.
func MarshalEnvelope(e *Envelope) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{e.Op})
	enc.AddID(2, putU32(e.ReqID))
	enc.AddID(3, e.Payload)
	return enc.Bytes()
}

// UnmarshalEnvelope decodes an envelope.
func UnmarshalEnvelope(body []byte) (*Envelope, error) {
	if len(body) == 0 || len(body) > MaxRPCBytes {
		return nil, fmt.Errorf("transport: rpc: bad envelope length %d", len(body))
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, fmt.Errorf("transport: rpc: %w", err)
	}
	out := &Envelope{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, fmt.Errorf("transport: rpc: bad op")
			}
			out.Op = f.Data[0]
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, fmt.Errorf("transport: rpc: %w", err)
			}
			out.ReqID = v
		case 3:
			out.Payload = append([]byte(nil), f.Data...)
		}
	}
	if out.Op != OpError && (out.Op < OpInitialize || out.Op > OpXferCancel) {
		return nil, fmt.Errorf("transport: rpc: unknown op %d", out.Op)
	}
	return out, nil
}

// Framing: [len BE32][NanoPack envelope body] on stdio.
func frameMessage(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

func putU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	out := make([]byte, 4)
	copy(out, b[:])
	return out
}

func getU32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, nanopack.ErrShortBody
	}
	return binary.BigEndian.Uint32(b), nil
}

func getU64(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, nanopack.ErrShortBody
	}
	return binary.BigEndian.Uint64(b), nil
}

func putU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	out := make([]byte, 8)
	copy(out, b[:])
	return out
}

// --- payload codecs ---

// MarshalInitialize: 1=transport_id, 2=api_version u8, 3=config bytes.
func MarshalInitialize(id string, api uint8, config []byte) ([]byte, error) {
	if id == "" || len(config) > 64*1024 {
		return nil, fmt.Errorf("transport: rpc: bad initialize")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte(id))
	enc.AddID(2, []byte{api})
	enc.AddID(3, config)
	return enc.Bytes()
}

// Initialize is the decoded schema 101.
type Initialize struct {
	TransportID string
	APIVersion  uint8
	Config      []byte
}

// UnmarshalInitialize decodes schema 101.
func UnmarshalInitialize(body []byte) (*Initialize, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Initialize{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransportID = string(append([]byte(nil), f.Data...))
		case 2:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.APIVersion = f.Data[0]
		case 3:
			out.Config = append([]byte(nil), f.Data...)
		}
	}
	if out.TransportID == "" {
		return nil, fmt.Errorf("transport: rpc: empty transport id")
	}
	return out, nil
}

// MarshalInitResult: 1=ok u8, 2=detail, 3=actual_api u8.
func MarshalInitResult(ok bool, detail string, api uint8) ([]byte, error) {
	enc := &nanopack.Encoder{}
	if ok {
		enc.AddID(1, []byte{1})
	} else {
		enc.AddID(1, []byte{0})
	}
	enc.AddID(2, []byte(detail))
	enc.AddID(3, []byte{api})
	return enc.Bytes()
}

// InitResult is the decoded schema 102.
type InitResult struct {
	OK        bool
	Detail    string
	ActualAPI uint8
}

// UnmarshalInitResult decodes schema 102.
func UnmarshalInitResult(body []byte) (*InitResult, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &InitResult{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.OK = f.Data[0] == 1
		case 2:
			out.Detail = string(append([]byte(nil), f.Data...))
		case 3:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.ActualAPI = f.Data[0]
		}
	}
	return out, nil
}

// MarshalSend: 1=frame bytes (opaque [type][nanopack]), 2=recipient_pub (0/32B),
// 3=sender_hint (0/32B, logging only — never a key), 4=mailbox_id (0/16B
// explicit recipient address), 5=shard_url for MailboxID.
func MarshalSend(frame, recipientPub, senderHint, mailboxID []byte, shardURL string) ([]byte, error) {
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return nil, fmt.Errorf("transport: rpc: frame out of bounds")
	}
	if len(recipientPub) != 0 && len(recipientPub) != 32 {
		return nil, fmt.Errorf("transport: rpc: recipient_pub must be 0 or 32 bytes")
	}
	if len(senderHint) != 0 && len(senderHint) != 32 {
		return nil, fmt.Errorf("transport: rpc: sender_hint must be 0 or 32 bytes")
	}
	if len(mailboxID) != 0 && len(mailboxID) != 16 {
		return nil, fmt.Errorf("transport: rpc: mailbox_id must be 0 or 16 bytes")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, frame)
	enc.AddID(2, recipientPub)
	enc.AddID(3, senderHint)
	enc.AddID(4, mailboxID)
	enc.AddID(5, []byte(shardURL))
	return enc.Bytes()
}

// Send is the decoded schema 103.
type Send struct {
	Frame        []byte
	RecipientPub []byte
	SenderHint   []byte
	MailboxID    []byte
	ShardURL     string
}

// UnmarshalSend decodes schema 103.
func UnmarshalSend(body []byte) (*Send, error) {
	if len(body) > MaxFrameBytes+1024 {
		return nil, fmt.Errorf("transport: rpc: send too large")
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Send{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.Frame = append([]byte(nil), f.Data...)
		case 2:
			out.RecipientPub = append([]byte(nil), f.Data...)
		case 3:
			out.SenderHint = append([]byte(nil), f.Data...)
		case 4:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 5:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.Frame) == 0 || len(out.Frame) > MaxFrameBytes {
		return nil, fmt.Errorf("transport: rpc: frame out of bounds")
	}
	return out, nil
}

// MarshalAck: 1=ok u8, 2=detail.
func MarshalAck(ok bool, detail string) ([]byte, error) {
	enc := &nanopack.Encoder{}
	if ok {
		enc.AddID(1, []byte{1})
	} else {
		enc.AddID(1, []byte{0})
	}
	enc.AddID(2, []byte(detail))
	return enc.Bytes()
}

// Ack is the decoded schema 104.
type Ack struct {
	OK     bool
	Detail string
}

// UnmarshalAck decodes schema 104.
func UnmarshalAck(body []byte) (*Ack, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Ack{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.OK = f.Data[0] == 1
		case 2:
			out.Detail = string(append([]byte(nil), f.Data...))
		}
	}
	return out, nil
}

// MarshalAttach: 1=mailbox_id 16B, 2=read_secret 32B bearer, 3=shard_url, 4=router_url.
func MarshalAttach(mailboxID, readSecret []byte, shardURL, routerURL string) ([]byte, error) {
	if len(mailboxID) != 16 || len(readSecret) != 32 || shardURL == "" {
		return nil, fmt.Errorf("transport: rpc: bad attach")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, mailboxID)
	enc.AddID(2, readSecret)
	enc.AddID(3, []byte(shardURL))
	enc.AddID(4, []byte(routerURL))
	return enc.Bytes()
}

// Attach is the decoded schema 105.
type Attach struct {
	MailboxID  []byte
	ReadSecret []byte
	ShardURL   string
	RouterURL  string
}

// UnmarshalAttach decodes schema 105.
func UnmarshalAttach(body []byte) (*Attach, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Attach{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 3:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		case 4:
			out.RouterURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.MailboxID) != 16 || len(out.ReadSecret) != 32 || out.ShardURL == "" {
		return nil, fmt.Errorf("transport: rpc: bad attach")
	}
	return out, nil
}

// MarshalDetach: 1=mailbox_id 16B.
func MarshalDetach(mailboxID []byte) ([]byte, error) {
	if len(mailboxID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad detach")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, mailboxID)
	return enc.Bytes()
}

// UnmarshalDetach decodes schema 106.
func UnmarshalDetach(body []byte) ([]byte, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	var id []byte
	for _, f := range fields {
		if f.ID == 1 {
			id = append([]byte(nil), f.Data...)
		}
	}
	if len(id) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad detach")
	}
	return id, nil
}

// MarshalPoll: 1=limit u8, 2=mailbox_id (0/16B, empty = all).
func MarshalPoll(limit uint8, mailboxID []byte) ([]byte, error) {
	if len(mailboxID) != 0 && len(mailboxID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad poll mailbox")
	}
	if limit == 0 {
		limit = 32
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{limit})
	enc.AddID(2, mailboxID)
	return enc.Bytes()
}

// Poll is the decoded schema 107.
type Poll struct {
	Limit     uint8
	MailboxID []byte
}

// UnmarshalPoll decodes schema 107.
func UnmarshalPoll(body []byte) (*Poll, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Poll{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Limit = f.Data[0]
		case 2:
			out.MailboxID = append([]byte(nil), f.Data...)
		}
	}
	if len(out.MailboxID) != 0 && len(out.MailboxID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad poll mailbox")
	}
	if out.Limit == 0 {
		out.Limit = 32
	}
	return out, nil
}

// MarshalPollResult: 1=frames blob (each BE32 len + full [type][payload] frame), 2=count u32.
func MarshalPollResult(frames [][]byte) ([]byte, error) {
	if len(frames) > 32 {
		return nil, fmt.Errorf("transport: rpc: too many frames")
	}
	var blob []byte
	for _, f := range frames {
		if len(f) == 0 || len(f) > MaxFrameBytes {
			return nil, fmt.Errorf("transport: rpc: frame out of bounds")
		}
		blob = append(blob, putU32(uint32(len(f)))...)
		blob = append(blob, f...)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, blob)
	enc.AddID(2, putU32(uint32(len(frames))))
	return enc.Bytes()
}

// UnmarshalPollResult decodes schema 108.
func UnmarshalPollResult(body []byte) ([][]byte, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	var blob []byte
	var count uint32
	var seenCount bool
	for _, f := range fields {
		switch f.ID {
		case 1:
			blob = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			count = v
			seenCount = true
		}
	}
	if !seenCount || count > 32 {
		return nil, fmt.Errorf("transport: rpc: bad poll result")
	}
	var out [][]byte
	pos := 0
	for uint32(len(out)) < count {
		if pos+4 > len(blob) {
			return nil, fmt.Errorf("transport: rpc: poll result truncated")
		}
		n := int(uint32(blob[pos])<<24 | uint32(blob[pos+1])<<16 | uint32(blob[pos+2])<<8 | uint32(blob[pos+3]))
		pos += 4
		if n <= 0 || n > MaxFrameBytes || pos+n > len(blob) {
			return nil, fmt.Errorf("transport: rpc: frame out of bounds")
		}
		out = append(out, append([]byte(nil), blob[pos:pos+n]...))
		pos += n
	}
	if pos != len(blob) {
		return nil, fmt.Errorf("transport: rpc: poll result trailing bytes")
	}
	return out, nil
}

// MarshalStatus: 1=running u8, 2=detail.
func MarshalStatus(running bool, detail string) ([]byte, error) {
	enc := &nanopack.Encoder{}
	if running {
		enc.AddID(1, []byte{1})
	} else {
		enc.AddID(1, []byte{0})
	}
	enc.AddID(2, []byte(detail))
	return enc.Bytes()
}

// Status is the decoded schema 110.
type Status struct {
	Running bool
	Detail  string
}

// UnmarshalStatus decodes schema 110.
func UnmarshalStatus(body []byte) (*Status, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Status{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			if len(f.Data) != 1 {
				return nil, nanopack.ErrShortBody
			}
			out.Running = f.Data[0] == 1
		case 2:
			out.Detail = string(append([]byte(nil), f.Data...))
		}
	}
	return out, nil
}

// MarshalCaps: 1=caps blob (each u16 BE len + bytes), 2=transport_id, 3=version.
func MarshalCaps(caps []string, id, version string) ([]byte, error) {
	var blob []byte
	for _, c := range caps {
		if len(c) == 0 || len(c) > 64 {
			return nil, fmt.Errorf("transport: rpc: bad capability")
		}
		blob = append(blob, byte(len(c)>>8), byte(len(c)))
		blob = append(blob, c...)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, blob)
	enc.AddID(2, []byte(id))
	enc.AddID(3, []byte(version))
	return enc.Bytes()
}

// Caps is the decoded schema 112.
type Caps struct {
	Capabilities []string
	TransportID  string
	Version      string
}

// UnmarshalCaps decodes schema 112.
func UnmarshalCaps(body []byte) (*Caps, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &Caps{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			pos := 0
			for pos < len(f.Data) {
				if pos+2 > len(f.Data) {
					return nil, nanopack.ErrShortBody
				}
				n := int(f.Data[pos])<<8 | int(f.Data[pos+1])
				pos += 2
				if n <= 0 || pos+n > len(f.Data) {
					return nil, nanopack.ErrShortBody
				}
				out.Capabilities = append(out.Capabilities, string(f.Data[pos:pos+n]))
				pos += n
			}
		case 2:
			out.TransportID = string(append([]byte(nil), f.Data...))
		case 3:
			out.Version = string(append([]byte(nil), f.Data...))
		}
	}
	if out.TransportID == "" {
		return nil, fmt.Errorf("transport: rpc: empty transport id")
	}
	return out, nil
}

// MarshalError: 1=code u32, 2=detail.
func MarshalError(code uint32, detail string) ([]byte, error) {
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(code))
	enc.AddID(2, []byte(detail))
	return enc.Bytes()
}

// RPCError is the decoded schema 113.
type RPCError struct {
	Code   uint32
	Detail string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("transport: rpc error %d: %s", e.Code, e.Detail)
}

// UnmarshalError decodes schema 113.
func UnmarshalError(body []byte) (*RPCError, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &RPCError{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Code = v
		case 2:
			out.Detail = string(append([]byte(nil), f.Data...))
		}
	}
	if out.Code == 0 {
		return nil, fmt.Errorf("transport: rpc: error code 0 reserved")
	}
	return out, nil
}

// MarshalStartStop: 1=action u8.
func MarshalStartStop(action uint8) ([]byte, error) {
	if action != ActionStart && action != ActionStop {
		return nil, fmt.Errorf("transport: rpc: bad action")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{action})
	return enc.Bytes()
}

// UnmarshalStartStop decodes schema 114.
func UnmarshalStartStop(body []byte) (uint8, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return 0, err
	}
	for _, f := range fields {
		if f.ID == 1 {
			if len(f.Data) != 1 {
				return 0, nanopack.ErrShortBody
			}
			if f.Data[0] != ActionStart && f.Data[0] != ActionStop {
				return 0, fmt.Errorf("transport: rpc: bad action")
			}
			return f.Data[0], nil
		}
	}
	return 0, fmt.Errorf("transport: rpc: missing action")
}
