package transport

import (
	"context"
	"fmt"
	"sort"
)

// FileTransport is the binary-transfer capability. Transports declaring
// "binary-transfer" implement it; message-only transports must not be
// asked (use RequiresFile to fail fast client-side instead of sending an
// op the peer cannot answer).
type FileTransport interface {
	FrameTransport
	// XferCreate opens a transfer for ciphertext of total bytes. The
	// returned ticket (transfer + download secret + shard) is what the
	// sender shares with the recipient inside an E2E message.
	XferCreate(ctx context.Context, total uint64, chunkSize, chunkCount uint32, manifest, mailboxID, recipientPub []byte, shardURL string) (*XferCreated, error)
	// XferPut uploads one chunk; returns highest-contiguous index count.
	XferPut(ctx context.Context, transferID []byte, index uint32, payload, hash []byte, offset uint64) (highest uint32, err error)
	// XferResume reports server truth (recipient side, bearer required).
	XferResume(ctx context.Context, transferID, mailboxID, readSecret []byte) (count, highest uint32, missing [][2]uint32, err error)
	// XferGet downloads one chunk (recipient side, bearer required).
	XferGet(ctx context.Context, transferID []byte, index uint32, mailboxID, readSecret []byte) (payload, hash []byte, err error)
	// XferResumeByTicket / XferGetByTicket use the download ticket from
	// XferCreate instead of any mailbox credential. No mailbox, no session,
	// no read_secret: the ticket + explicit shardURL are self-contained.
	// Download-only; put/complete/cancel never accept tickets.
	XferResumeByTicket(ctx context.Context, transferID, ticket []byte, shardURL string) (count, highest uint32, missing [][2]uint32, err error)
	XferGetByTicket(ctx context.Context, transferID []byte, index uint32, ticket []byte, shardURL string) (payload, hash []byte, err error)
	// XferComplete seals a fully-uploaded transfer.
	XferComplete(ctx context.Context, transferID, manifestHash []byte) error
	// XferCancel aborts a transfer. Mailbox-owner auth only (mailbox bearer);
	// download tickets never cancel — a recipient cannot destroy the
	// sender's upload.
	XferCancel(ctx context.Context, transferID, mailboxID, readSecret []byte) error
	// RegisterBox mints a mailbox via the transport's scoped credential.
	XferRegister(ctx context.Context, userTag, routerURL string) (mailboxID, readSecret []byte, shardURL, outRouter string, err error)
	// XferResolve maps a recipient pubkey to its mailbox + shard.
	XferResolve(ctx context.Context, recipientPub []byte, routerURL string) (mailboxID []byte, shardURL string, err error)
}

// RequiresFile asserts t implements FileTransport (capability gate).
func RequiresFile(t FrameTransport) (FileTransport, error) {
	ft, ok := t.(FileTransport)
	if !ok {
		return nil, &RPCError{Code: ErrUnsupported, Detail: fmt.Sprintf("transport %q lacks binary-transfer", t.ID())}
	}
	return ft, nil
}

// FileRoute returns running transports declaring binary-transfer.
func (m *Manager) FileRoute() []FileTransport {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FileTransport
	for _, t := range m.live {
		ft, ok := t.(FileTransport)
		if !ok {
			continue
		}
		for _, c := range t.Capabilities() {
			if c == "binary-transfer" {
				out = append(out, ft)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// --- ProcessTransport file methods ---

func (t *ProcessTransport) XferCreate(ctx context.Context, total uint64, chunkSize, chunkCount uint32, manifest, mailboxID, recipientPub []byte, shardURL string) (*XferCreated, error) {
	payload, err := MarshalXferCreate(total, chunkSize, chunkCount, manifest, mailboxID, recipientPub, shardURL)
	if err != nil {
		return nil, err
	}
	env, err := t.proc.Call(ctx, OpXferCreate, payload)
	if err != nil {
		return nil, err
	}
	created, err := UnmarshalXferCreated(env.Payload)
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (t *ProcessTransport) XferPut(ctx context.Context, transferID []byte, index uint32, payload, hash []byte, offset uint64) (uint32, error) {
	body, err := MarshalXferPut(transferID, index, payload, hash, offset)
	if err != nil {
		return 0, err
	}
	env, err := t.proc.Call(ctx, OpXferPut, body)
	if err != nil {
		return 0, err
	}
	prog, err := UnmarshalXferProgress(env.Payload)
	if err != nil {
		return 0, err
	}
	return prog.Highest, nil
}

func decodeRanges(blob []byte) ([][2]uint32, error) {
	if len(blob)%8 != 0 {
		return nil, fmt.Errorf("transport: rpc: bad ranges")
	}
	var out [][2]uint32
	for i := 0; i < len(blob); i += 8 {
		s := uint32(blob[i])<<24 | uint32(blob[i+1])<<16 | uint32(blob[i+2])<<8 | uint32(blob[i+3])
		c := uint32(blob[i+4])<<24 | uint32(blob[i+5])<<16 | uint32(blob[i+6])<<8 | uint32(blob[i+7])
		out = append(out, [2]uint32{s, c})
	}
	return out, nil
}

func (t *ProcessTransport) XferResume(ctx context.Context, transferID, mailboxID, readSecret []byte) (uint32, uint32, [][2]uint32, error) {
	body, err := MarshalXferResume(transferID, mailboxID, readSecret, nil, "")
	if err != nil {
		return 0, 0, nil, err
	}
	env, err := t.proc.Call(ctx, OpXferResume, body)
	if err != nil {
		return 0, 0, nil, err
	}
	prog, err := UnmarshalXferProgress(env.Payload)
	if err != nil {
		return 0, 0, nil, err
	}
	missing, err := decodeRanges(prog.MissingRanges)
	if err != nil {
		return 0, 0, nil, err
	}
	return prog.Count, prog.Highest, missing, nil
}

func (t *ProcessTransport) XferGet(ctx context.Context, transferID []byte, index uint32, mailboxID, readSecret []byte) ([]byte, []byte, error) {
	body, err := MarshalXferGet(transferID, index, mailboxID, readSecret, nil, "")
	if err != nil {
		return nil, nil, err
	}
	env, err := t.proc.Call(ctx, OpXferGet, body)
	if err != nil {
		return nil, nil, err
	}
	chunk, err := UnmarshalXferChunk(env.Payload)
	if err != nil {
		return nil, nil, err
	}
	return chunk.Payload, chunk.Hash, nil
}

func (t *ProcessTransport) XferResumeByTicket(ctx context.Context, transferID, ticket []byte, shardURL string) (uint32, uint32, [][2]uint32, error) {
	body, err := MarshalXferResume(transferID, nil, nil, ticket, shardURL)
	if err != nil {
		return 0, 0, nil, err
	}
	env, err := t.proc.Call(ctx, OpXferResume, body)
	if err != nil {
		return 0, 0, nil, err
	}
	prog, err := UnmarshalXferProgress(env.Payload)
	if err != nil {
		return 0, 0, nil, err
	}
	missing, err := decodeRanges(prog.MissingRanges)
	if err != nil {
		return 0, 0, nil, err
	}
	return prog.Count, prog.Highest, missing, nil
}

func (t *ProcessTransport) XferGetByTicket(ctx context.Context, transferID []byte, index uint32, ticket []byte, shardURL string) ([]byte, []byte, error) {
	body, err := MarshalXferGet(transferID, index, nil, nil, ticket, shardURL)
	if err != nil {
		return nil, nil, err
	}
	env, err := t.proc.Call(ctx, OpXferGet, body)
	if err != nil {
		return nil, nil, err
	}
	chunk, err := UnmarshalXferChunk(env.Payload)
	if err != nil {
		return nil, nil, err
	}
	return chunk.Payload, chunk.Hash, nil
}

func (t *ProcessTransport) XferComplete(ctx context.Context, transferID, manifestHash []byte) error {
	body, err := MarshalXferCompleteReq(transferID, manifestHash)
	if err != nil {
		return err
	}
	env, err := t.proc.Call(ctx, OpXferComplete, body)
	if err != nil {
		return err
	}
	ack, err := UnmarshalAck(env.Payload)
	if err != nil {
		return err
	}
	if !ack.OK {
		return &RPCError{Code: ErrTransport, Detail: ack.Detail}
	}
	return nil
}

func (t *ProcessTransport) XferCancel(ctx context.Context, transferID, mailboxID, readSecret []byte) error {
	body, err := MarshalXferCancelReq(transferID, mailboxID, readSecret)
	if err != nil {
		return err
	}
	env, err := t.proc.Call(ctx, OpXferCancel, body)
	if err != nil {
		return err
	}
	ack, err := UnmarshalAck(env.Payload)
	if err != nil {
		return err
	}
	if !ack.OK {
		return &RPCError{Code: ErrTransport, Detail: ack.Detail}
	}
	return nil
}

func (t *ProcessTransport) XferRegister(ctx context.Context, userTag, routerURL string) ([]byte, []byte, string, string, error) {
	body, err := MarshalRegisterReq(userTag, routerURL)
	if err != nil {
		return nil, nil, "", "", err
	}
	env, err := t.proc.Call(ctx, OpRegister, body)
	if err != nil {
		return nil, nil, "", "", err
	}
	res, err := UnmarshalRegisterResult(env.Payload)
	if err != nil {
		return nil, nil, "", "", err
	}
	return res.MailboxID, res.ReadSecret, res.ShardURL, res.RouterURL, nil
}

func (t *ProcessTransport) XferResolve(ctx context.Context, recipientPub []byte, routerURL string) ([]byte, string, error) {
	body, err := MarshalResolveReq(recipientPub, routerURL)
	if err != nil {
		return nil, "", err
	}
	env, err := t.proc.Call(ctx, OpResolve, body)
	if err != nil {
		return nil, "", err
	}
	res, err := UnmarshalResolveResult(env.Payload)
	if err != nil {
		return nil, "", err
	}
	return res.MailboxID, res.ShardURL, nil
}
