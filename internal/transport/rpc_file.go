package transport

import (
	"fmt"

	"github.com/erfanheydarzade/nanopack"
)

// File/mailbox codecs for the binary-transfer capability and courier-model
// mailbox management (schemas 115–126). Size bounds mirror the FileRelay
// limits so hostile transports cannot force over-allocation in core.

// MaxXferManifest bounds the opaque transfer manifest core passes through.
const MaxXferManifest = 4096

// --- register (op 9) ---

// MarshalRegisterReq: 1=user_tag, 2=router_url.
func MarshalRegisterReq(userTag, routerURL string) ([]byte, error) {
	if userTag == "" || len(userTag) > 128 || len(routerURL) > 512 {
		return nil, fmt.Errorf("transport: rpc: bad register request")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte(userTag))
	enc.AddID(2, []byte(routerURL))
	return enc.Bytes()
}

// RegisterReq is the decoded schema 123.
type RegisterReq struct {
	UserTag   string
	RouterURL string
}

// UnmarshalRegisterReq decodes schema 123.
func UnmarshalRegisterReq(body []byte) (*RegisterReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &RegisterReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.UserTag = string(append([]byte(nil), f.Data...))
		case 2:
			out.RouterURL = string(append([]byte(nil), f.Data...))
		}
	}
	if out.UserTag == "" {
		return nil, fmt.Errorf("transport: rpc: bad register request")
	}
	return out, nil
}

// MarshalRegisterResult: 1=mailbox_id 16B, 2=read_secret 32B, 3=shard_url, 4=router_url.
func MarshalRegisterResult(mailboxID, readSecret []byte, shardURL, routerURL string) ([]byte, error) {
	if len(mailboxID) != 16 || len(readSecret) != 32 || shardURL == "" {
		return nil, fmt.Errorf("transport: rpc: bad register result")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, mailboxID)
	enc.AddID(2, readSecret)
	enc.AddID(3, []byte(shardURL))
	enc.AddID(4, []byte(routerURL))
	return enc.Bytes()
}

// RegisterResult is the decoded schema 124.
type RegisterResult struct {
	MailboxID  []byte
	ReadSecret []byte
	ShardURL   string
	RouterURL  string
}

// UnmarshalRegisterResult decodes schema 124.
func UnmarshalRegisterResult(body []byte) (*RegisterResult, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &RegisterResult{}
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
		return nil, fmt.Errorf("transport: rpc: bad register result")
	}
	return out, nil
}

// --- resolve (op 10) ---

// MarshalResolveReq: 1=recipient_pub 32B, 2=router_url.
func MarshalResolveReq(recipientPub []byte, routerURL string) ([]byte, error) {
	if len(recipientPub) != 32 {
		return nil, fmt.Errorf("transport: rpc: recipient_pub must be 32 bytes")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, recipientPub)
	enc.AddID(2, []byte(routerURL))
	return enc.Bytes()
}

// ResolveReq is the decoded schema 125.
type ResolveReq struct {
	RecipientPub []byte
	RouterURL    string
}

// UnmarshalResolveReq decodes schema 125.
func UnmarshalResolveReq(body []byte) (*ResolveReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ResolveReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.RecipientPub = append([]byte(nil), f.Data...)
		case 2:
			out.RouterURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.RecipientPub) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad resolve request")
	}
	return out, nil
}

// MarshalResolveResult: 1=mailbox_id 16B, 2=shard_url.
func MarshalResolveResult(mailboxID []byte, shardURL string) ([]byte, error) {
	if len(mailboxID) != 16 || shardURL == "" {
		return nil, fmt.Errorf("transport: rpc: bad resolve result")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, mailboxID)
	enc.AddID(2, []byte(shardURL))
	return enc.Bytes()
}

// ResolveResult is the decoded schema 126.
type ResolveResult struct {
	MailboxID []byte
	ShardURL  string
}

// UnmarshalResolveResult decodes schema 126.
func UnmarshalResolveResult(body []byte) (*ResolveResult, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &ResolveResult{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 2:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.MailboxID) != 16 || out.ShardURL == "" {
		return nil, fmt.Errorf("transport: rpc: bad resolve result")
	}
	return out, nil
}

// --- xfer create (op 11) ---

// MarshalXferCreate: 1=total u64, 2=chunk_size u32, 3=chunk_count u32,
// 4=manifest (<=4KiB), 5=mailbox_id (0/16B explicit recipient address),
// 6=recipient_pub (0/32B), 7=shard_url for MailboxID.
func MarshalXferCreate(total uint64, chunkSize, chunkCount uint32, manifest, mailboxID, recipientPub []byte, shardURL string) ([]byte, error) {
	if len(manifest) > MaxXferManifest {
		return nil, fmt.Errorf("transport: rpc: manifest too large")
	}
	if len(mailboxID) != 0 && len(mailboxID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad mailbox")
	}
	if len(recipientPub) != 0 && len(recipientPub) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad recipient")
	}
	if chunkSize == 0 || chunkSize > 64*1024 || chunkCount == 0 || chunkCount > 16384 || total == 0 {
		return nil, fmt.Errorf("transport: rpc: bad transfer params")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU64(total))
	enc.AddID(2, putU32(chunkSize))
	enc.AddID(3, putU32(chunkCount))
	enc.AddID(4, manifest)
	enc.AddID(5, mailboxID)
	enc.AddID(6, recipientPub)
	enc.AddID(7, []byte(shardURL))
	return enc.Bytes()
}

// XferCreate is the decoded schema 115.
type XferCreate struct {
	Total        uint64
	ChunkSize    uint32
	ChunkCount   uint32
	Manifest     []byte
	MailboxID    []byte
	RecipientPub []byte
	ShardURL     string
}

// UnmarshalXferCreate decodes schema 115.
func UnmarshalXferCreate(body []byte) (*XferCreate, error) {
	if len(body) > MaxXferManifest+256 {
		return nil, fmt.Errorf("transport: rpc: create too large")
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferCreate{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.Total = v
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkSize = v
		case 3:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.ChunkCount = v
		case 4:
			out.Manifest = append([]byte(nil), f.Data...)
		case 5:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 6:
			out.RecipientPub = append([]byte(nil), f.Data...)
		case 7:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if out.Total == 0 || out.ChunkSize == 0 || out.ChunkSize > 64*1024 || out.ChunkCount == 0 || out.ChunkCount > 16384 {
		return nil, fmt.Errorf("transport: rpc: bad transfer params")
	}
	return out, nil
}

// MarshalXferCreated: 1=transfer_id 16B, 2=expires u64,
// 3=download_secret 32B (ticket bearer), 4=shard_url.
func MarshalXferCreated(transferID, downloadSecret []byte, shardURL string, expires uint64) ([]byte, error) {
	if len(transferID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad transfer id")
	}
	if len(downloadSecret) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad download secret")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, putU64(expires))
	enc.AddID(3, downloadSecret)
	enc.AddID(4, []byte(shardURL))
	return enc.Bytes()
}

// XferCreated is the decoded schema 116.
type XferCreated struct {
	TransferID     []byte
	Expires        uint64
	DownloadSecret []byte
	ShardURL       string
}

// UnmarshalXferCreated decodes schema 116.
func UnmarshalXferCreated(body []byte) (*XferCreated, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferCreated{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.Expires = v
		case 3:
			out.DownloadSecret = append([]byte(nil), f.Data...)
		case 4:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.TransferID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad transfer id")
	}
	if len(out.DownloadSecret) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad download secret (transport too old for tickets?)")
	}
	return out, nil
}

// --- xfer put (op 12) ---

// MarshalXferPut: 1=transfer_id 16B, 2=index u32, 3=payload (<=64KiB),
// 4=hash 32B, 5=offset u64.
func MarshalXferPut(transferID []byte, index uint32, payload, hash []byte, offset uint64) ([]byte, error) {
	if len(transferID) != 16 || len(payload) == 0 || len(payload) > 64*1024 || len(hash) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad chunk")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, putU32(index))
	enc.AddID(3, payload)
	enc.AddID(4, hash)
	enc.AddID(5, putU64(offset))
	return enc.Bytes()
}

// XferPut is the decoded schema 117.
type XferPut struct {
	TransferID []byte
	Index      uint32
	Payload    []byte
	Hash       []byte
	Offset     uint64
}

// UnmarshalXferPut decodes schema 117.
func UnmarshalXferPut(body []byte) (*XferPut, error) {
	if len(body) > 64*1024+256 {
		return nil, fmt.Errorf("transport: rpc: chunk too large")
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferPut{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Index = v
		case 3:
			out.Payload = append([]byte(nil), f.Data...)
		case 4:
			out.Hash = append([]byte(nil), f.Data...)
		case 5:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, err
			}
			out.Offset = v
		}
	}
	if len(out.TransferID) != 16 || len(out.Payload) == 0 || len(out.Hash) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad chunk")
	}
	return out, nil
}

// --- xfer progress (op 12/13 response, schema 118) ---

// MarshalXferProgress: 1=highest u32, 2=missing_ranges flat, 3=bitmap,
// 4=encoding u8, 5=chunk_count u32.
func MarshalXferProgress(highest, count uint32, missingRanges, bitmap []byte, encoding uint8) ([]byte, error) {
	if len(missingRanges)%8 != 0 || len(missingRanges) > 8*1024 {
		return nil, fmt.Errorf("transport: rpc: bad ranges")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, putU32(highest))
	enc.AddID(2, missingRanges)
	enc.AddID(3, bitmap)
	enc.AddID(4, []byte{encoding})
	enc.AddID(5, putU32(count))
	return enc.Bytes()
}

// XferProgress is the decoded schema 118.
type XferProgress struct {
	Highest       uint32
	Count         uint32
	MissingRanges []byte
	Bitmap        []byte
	Encoding      uint8
}

// UnmarshalXferProgress decodes schema 118.
func UnmarshalXferProgress(body []byte) (*XferProgress, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferProgress{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Highest = v
		case 2:
			out.MissingRanges = append([]byte(nil), f.Data...)
		case 3:
			out.Bitmap = append([]byte(nil), f.Data...)
		case 4:
			if len(f.Data) != 1 {
				return nil, fmt.Errorf("transport: rpc: bad encoding")
			}
			out.Encoding = f.Data[0]
		case 5:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Count = v
		}
	}
	if len(out.MissingRanges)%8 != 0 {
		return nil, fmt.Errorf("transport: rpc: bad ranges")
	}
	return out, nil
}

// --- xfer resume (op 13, schema 119) ---

// MarshalXferResume: 1=transfer_id 16B, 2=mailbox_id 16B, 3=read_secret 32B,
// 4=ticket 32B (XOR with 2+3), 5=shard_url for ticket mode.
func MarshalXferResume(transferID, mailboxID, readSecret, ticket []byte, shardURL string) ([]byte, error) {
	if len(transferID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad resume")
	}
	if err := checkXferAuth(mailboxID, readSecret, ticket); err != nil {
		return nil, err
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, mailboxID)
	enc.AddID(3, readSecret)
	enc.AddID(4, ticket)
	enc.AddID(5, []byte(shardURL))
	return enc.Bytes()
}

// checkXferAuth enforces exactly one auth context: mailbox bearer
// (mailbox 16B + secret 32B) or download ticket (32B, mailbox + secret empty).
func checkXferAuth(mailboxID, readSecret, ticket []byte) error {
	if len(ticket) == 32 {
		if len(mailboxID) != 0 || len(readSecret) != 0 {
			return fmt.Errorf("transport: rpc: ticket mode: mailbox and read_secret must be empty")
		}
		return nil
	}
	if len(ticket) != 0 {
		return fmt.Errorf("transport: rpc: ticket must be 32 bytes")
	}
	if len(mailboxID) != 16 || len(readSecret) != 32 {
		return fmt.Errorf("transport: rpc: bad resume")
	}
	return nil
}

// XferResume is the decoded schema 119.
type XferResume struct {
	TransferID []byte
	MailboxID  []byte
	ReadSecret []byte
	Ticket     []byte
	ShardURL   string
}

// UnmarshalXferResume decodes schema 119.
func UnmarshalXferResume(body []byte) (*XferResume, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferResume{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 3:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 4:
			out.Ticket = append([]byte(nil), f.Data...)
		case 5:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.TransferID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad resume")
	}
	if err := checkXferAuth(out.MailboxID, out.ReadSecret, out.Ticket); err != nil {
		return nil, err
	}
	return out, nil
}

// --- xfer get (op 14, schema 120) / chunk (schema 121) ---

// MarshalXferGet: 1=transfer_id 16B, 2=index u32, 3=mailbox_id 16B,
// 4=read_secret 32B, 5=ticket 32B (XOR with 3+4), 6=shard_url.
func MarshalXferGet(transferID []byte, index uint32, mailboxID, readSecret, ticket []byte, shardURL string) ([]byte, error) {
	if len(transferID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad get")
	}
	if err := checkXferAuth(mailboxID, readSecret, ticket); err != nil {
		return nil, fmt.Errorf("transport: rpc: bad get: %v", err)
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, putU32(index))
	enc.AddID(3, mailboxID)
	enc.AddID(4, readSecret)
	enc.AddID(5, ticket)
	enc.AddID(6, []byte(shardURL))
	return enc.Bytes()
}

// XferGet is the decoded schema 120.
type XferGet struct {
	TransferID []byte
	Index      uint32
	MailboxID  []byte
	ReadSecret []byte
	Ticket     []byte
	ShardURL   string
}

// UnmarshalXferGet decodes schema 120.
func UnmarshalXferGet(body []byte) (*XferGet, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferGet{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, err
			}
			out.Index = v
		case 3:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 4:
			out.ReadSecret = append([]byte(nil), f.Data...)
		case 5:
			out.Ticket = append([]byte(nil), f.Data...)
		case 6:
			out.ShardURL = string(append([]byte(nil), f.Data...))
		}
	}
	if len(out.TransferID) != 16 {
		return nil, fmt.Errorf("transport: rpc: bad get")
	}
	if err := checkXferAuth(out.MailboxID, out.ReadSecret, out.Ticket); err != nil {
		return nil, fmt.Errorf("transport: rpc: bad get: %v", err)
	}
	return out, nil
}

// MarshalXferChunk: 1=payload, 2=hash 32B.
func MarshalXferChunk(payload, hash []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > 64*1024 || len(hash) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad chunk data")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, payload)
	enc.AddID(2, hash)
	return enc.Bytes()
}

// XferChunk is the decoded schema 121.
type XferChunk struct {
	Payload []byte
	Hash    []byte
}

// UnmarshalXferChunk decodes schema 121.
func UnmarshalXferChunk(body []byte) (*XferChunk, error) {
	if len(body) > 64*1024+128 {
		return nil, fmt.Errorf("transport: rpc: chunk too large")
	}
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferChunk{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.Payload = append([]byte(nil), f.Data...)
		case 2:
			out.Hash = append([]byte(nil), f.Data...)
		}
	}
	if len(out.Payload) == 0 || len(out.Hash) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad chunk data")
	}
	return out, nil
}

// --- xfer complete (op 15, schema 122) ---

// MarshalXferCompleteReq: 1=transfer_id 16B, 2=manifest_hash 32B.
func MarshalXferCompleteReq(transferID, manifestHash []byte) ([]byte, error) {
	if len(transferID) != 16 || len(manifestHash) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad complete")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, manifestHash)
	return enc.Bytes()
}

// XferCompleteReq is the decoded schema 122.
type XferCompleteReq struct {
	TransferID   []byte
	ManifestHash []byte
}

// UnmarshalXferCompleteReq decodes schema 122.
func UnmarshalXferCompleteReq(body []byte) (*XferCompleteReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferCompleteReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			out.ManifestHash = append([]byte(nil), f.Data...)
		}
	}
	if len(out.TransferID) != 16 || len(out.ManifestHash) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad complete")
	}
	return out, nil
}

// --- xfer cancel (op 16, schema 127) ---

// MarshalXferCancelReq: 1=transfer_id 16B, 2=mailbox_id 16B, 3=read_secret 32B.
// Mailbox-owner auth only — tickets never cancel (see FileRelay TransferCancel).
func MarshalXferCancelReq(transferID, mailboxID, readSecret []byte) ([]byte, error) {
	if len(transferID) != 16 || len(mailboxID) != 16 || len(readSecret) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad cancel")
	}
	enc := &nanopack.Encoder{}
	enc.AddID(1, transferID)
	enc.AddID(2, mailboxID)
	enc.AddID(3, readSecret)
	return enc.Bytes()
}

// XferCancelReq is the decoded schema 127.
type XferCancelReq struct {
	TransferID []byte
	MailboxID  []byte
	ReadSecret []byte
}

// UnmarshalXferCancelReq decodes schema 127.
func UnmarshalXferCancelReq(body []byte) (*XferCancelReq, error) {
	fields, err := nanopack.DecodeID(body)
	if err != nil {
		return nil, err
	}
	out := &XferCancelReq{}
	for _, f := range fields {
		switch f.ID {
		case 1:
			out.TransferID = append([]byte(nil), f.Data...)
		case 2:
			out.MailboxID = append([]byte(nil), f.Data...)
		case 3:
			out.ReadSecret = append([]byte(nil), f.Data...)
		}
	}
	if len(out.TransferID) != 16 || len(out.MailboxID) != 16 || len(out.ReadSecret) != 32 {
		return nil, fmt.Errorf("transport: rpc: bad cancel")
	}
	return out, nil
}
