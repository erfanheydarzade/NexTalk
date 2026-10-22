package ntxhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/filetransfer"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// Transfer limits for the browser build.
const (
	MaxXferBytes     = 8 << 20
	DefaultChunkSize = 32 * 1024
	maxChunkCount    = 1 << 14
)

// Progress receives (done, total) in chunks. May be nil.
type Progress func(done, total int)

// XferSendParams describes one upload.
type XferSendParams struct {
	Peer      string // recipient peer ID (the E2E session key)
	Name      string
	Data      []byte
	Mailbox   string // optional explicit mailbox (32 hex) + Shard
	Shard     string
	ChunkSize int
	Progress  Progress
}

// XferSent is the result of XferSend.
type XferSent struct {
	Ticket     string `json:"ticket"`
	TransferID string `json:"transfer_id"`
	Expires    uint64 `json:"expires"`
}

// fileTransport returns the FileTransport for id, enforcing BOTH the
// manifest capability and the interface. WASM ABI v1 modules cannot
// implement xfer-create/put/complete, so against them this returns a clear
// error instead of pretending.
func (h *Host) fileTransport(ctx context.Context, id string) (transport.FileTransport, error) {
	tr, pkg, err := h.ensure(ctx, id)
	if err != nil {
		return nil, err
	}
	if !pkg.Manifest.HasCapability("binary-transfer") {
		return nil, fmt.Errorf("ntxhost: %q does not declare the \"binary-transfer\" capability", id)
	}
	ft, err := transport.RequiresFile(tr)
	if err != nil {
		return nil, fmt.Errorf("ntxhost: %q declares binary-transfer but its runtime exposes no transfer operations (WASM ABI v1 has none)", id)
	}
	return ft, nil
}

func cleanName(n string) string {
	n = strings.ReplaceAll(n, "\\", "/")
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSpace(n)
	if n == "" || n == "." || n == ".." {
		return "file"
	}
	return n
}

// XferSend E2E-encrypts the whole file, chunks it, uploads the chunks and
// seals the transfer. The returned ticket carries the download secret: send
// it to the recipient inside an E2E message.
func (h *Host) XferSend(ctx context.Context, id string, p XferSendParams) (*XferSent, error) {
	if len(p.Data) == 0 {
		return nil, fmt.Errorf("ntxhost: xfer: empty data")
	}
	if len(p.Data) > MaxXferBytes {
		return nil, fmt.Errorf("ntxhost: xfer: file is %d bytes, max %d", len(p.Data), MaxXferBytes)
	}
	ident, err := h.identity()
	if err != nil {
		return nil, err
	}
	ft, err := h.fileTransport(ctx, id)
	if err != nil {
		return nil, err
	}
	hint, err := routeHint(p.Peer, ident.Client.IdentityPublic, SendOptions{Mailbox: p.Mailbox, Shard: p.Shard})
	if err != nil {
		return nil, err
	}
	chunkSize := p.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if ident.Lock != nil {
		ident.Lock.Lock()
	}
	cipher, chunks, mf, err := filetransfer.EncryptFile(ident.Client, p.Peer, cleanName(p.Name), p.Data, chunkSize)
	if ident.Lock != nil {
		ident.Lock.Unlock()
	}
	if err != nil {
		return nil, err
	}
	// With an explicit mailbox the peer pub is not used for routing (CLI parity).
	var pub []byte
	if hint.MailboxID == nil {
		pub = hint.RecipientPub
	}
	created, err := ft.XferCreate(ctx, uint64(len(cipher)), uint32(mf.ChunkSize), uint32(mf.ChunkCount), mf.Bytes(), hint.MailboxID, pub, hint.ShardURL)
	if err != nil {
		return nil, fmt.Errorf("create: %w", err)
	}
	for i, chunk := range chunks {
		hh := sha256.Sum256(chunk)
		if _, err := ft.XferPut(ctx, created.TransferID, uint32(i), chunk, hh[:], uint64(i*mf.ChunkSize)); err != nil {
			return nil, fmt.Errorf("put %d: %w", i, err)
		}
		if p.Progress != nil {
			p.Progress(i+1, len(chunks))
		}
	}
	cipherHash := sha256.Sum256(cipher)
	if err := ft.XferComplete(ctx, created.TransferID, cipherHash[:]); err != nil {
		return nil, fmt.Errorf("complete: %w", err)
	}
	raw, err := filetransfer.MarshalTicket(&filetransfer.Ticket{
		Transfer: created.TransferID,
		Secret:   created.DownloadSecret,
		Shard:    created.ShardURL,
		Manifest: mf.Bytes(),
		From:     ident.Client.Id,
	})
	if err != nil {
		return nil, err
	}
	return &XferSent{
		Ticket:     filetransfer.EncodeTicketString(raw),
		TransferID: hex.EncodeToString(created.TransferID),
		Expires:    created.Expires,
	}, nil
}

// XferReceiveParams describes one download.
type XferReceiveParams struct {
	Ticket   string
	From     string // expected sender peer ID; "" falls back to ticket.From
	Progress Progress
}

// XferReceive downloads by ticket, verifies every chunk hash, reassembles
// and decrypts. The manifest comes from the (attacker-influenced) ticket, so
// its sizes are bounded before anything is allocated.
func (h *Host) XferReceive(ctx context.Context, id string, p XferReceiveParams) (name string, data []byte, err error) {
	ident, err := h.identity()
	if err != nil {
		return "", nil, err
	}
	raw, err := filetransfer.DecodeTicketString(p.Ticket)
	if err != nil {
		return "", nil, err
	}
	tk, err := filetransfer.ParseTicket(raw)
	if err != nil {
		return "", nil, err
	}
	mf, err := filetransfer.ParseManifest(tk.Manifest)
	if err != nil {
		return "", nil, err
	}
	if mf.PlainSize < 0 || mf.PlainSize > MaxXferBytes || mf.CipherSize < 0 || mf.CipherSize > MaxXferBytes+(1<<20) ||
		mf.ChunkCount <= 0 || mf.ChunkCount > maxChunkCount {
		return "", nil, fmt.Errorf("ntxhost: xfer: ticket describes a transfer outside this build's limits")
	}
	peer := p.From
	if peer == "" {
		peer = tk.From
	}
	if peer == "" {
		return "", nil, fmt.Errorf("ntxhost: xfer: expected sender unknown: pass { from }")
	}
	ft, err := h.fileTransport(ctx, id)
	if err != nil {
		return "", nil, err
	}
	_, highest, missing, err := ft.XferResumeByTicket(ctx, tk.Transfer, tk.Secret, tk.Shard)
	if err != nil {
		return "", nil, fmt.Errorf("resume: %w", err)
	}
	if len(missing) > 0 {
		return "", nil, fmt.Errorf("transfer incomplete (highest=%d, %d missing ranges); retry later", highest, len(missing))
	}
	chunks := make([][]byte, mf.ChunkCount)
	for i := range chunks {
		payload, want, err := ft.XferGetByTicket(ctx, tk.Transfer, uint32(i), tk.Secret, tk.Shard)
		if err != nil {
			return "", nil, fmt.Errorf("get %d: %w", i, err)
		}
		if got := sha256.Sum256(payload); hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
			return "", nil, fmt.Errorf("chunk %d hash mismatch", i)
		}
		chunks[i] = payload
		if p.Progress != nil {
			p.Progress(i+1, len(chunks))
		}
	}
	if ident.Lock != nil {
		ident.Lock.Lock()
		defer ident.Lock.Unlock()
	}
	plain, err := filetransfer.ReassembleAndDecrypt(ident.Client, peer, chunks, mf)
	if err != nil {
		return "", nil, err
	}
	return cleanName(mf.FileName), plain, nil
}

// TicketInfo is display-only ticket metadata.
type TicketInfo struct {
	TransferID string  `json:"transfer_id"`
	Shard      string  `json:"shard"`
	Name       string  `json:"name"`
	Size       int     `json:"size"`
	Sender     string  `json:"sender"`
	Expires    *uint64 `json:"expires"` // tickets carry no expiry; always null
}

// DescribeTicket parses a ticket for display. It contacts nothing and does
// not expose the download secret.
func DescribeTicket(ticketB64 string) (*TicketInfo, error) {
	raw, err := filetransfer.DecodeTicketString(ticketB64)
	if err != nil {
		return nil, err
	}
	tk, err := filetransfer.ParseTicket(raw)
	if err != nil {
		return nil, err
	}
	mf, err := filetransfer.ParseManifest(tk.Manifest)
	if err != nil {
		return nil, err
	}
	return &TicketInfo{
		TransferID: hex.EncodeToString(tk.Transfer),
		Shard:      tk.Shard,
		Name:       cleanName(mf.FileName),
		Size:       mf.PlainSize,
		Sender:     tk.From,
	}, nil
}
