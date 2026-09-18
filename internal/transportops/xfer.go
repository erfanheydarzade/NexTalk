package transportops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/filetransfer"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	ntx "github.com/erfanheydarzade/NexTalk/internal/transport"
)

// XferSendParams encrypts a local file and uploads it in chunks.
type XferSendParams struct {
	TransportID string
	Identity    string // local peer ID; "" falls back to session identity
	Peer        string // recipient peer ID (encryption session, required)
	MailboxID   string // explicit mailbox hex; "" derives routing from Peer
	ShardURL    string // required with MailboxID
	File        string
	ChunkSize   int
}

// XferSend encrypts, uploads, seals, and reports a shareable ticket.
// The ticket base64 prints in full: it is the designed handoff artifact
// (like a QR payload). Raw bearer flags stay redacted unless enabled.
func XferSend(d *Deps, p XferSendParams) error {
	identity := p.Identity
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	raw, err := os.ReadFile(p.File)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	cl, err := Client.LoadClient(identity)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, p.TransportID)
	if err != nil {
		return err
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		return err
	}
	var pub, mbox []byte
	pub, err = resolveRecipient(p.Peer)
	if err != nil {
		return err
	}
	if p.MailboxID != "" {
		mbox, err = hex.DecodeString(p.MailboxID)
		if err != nil || len(mbox) != 16 {
			return fmt.Errorf("mailbox must be 32 hex chars")
		}
		if p.ShardURL == "" {
			return fmt.Errorf("--shard is required with --mailbox")
		}
		pub = nil // explicit address wins; peer pub unused for routing
	}
	chunkSize := p.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 32 * 1024
	}
	cipher, chunks, mf, err := filetransfer.EncryptFile(cl, p.Peer, baseName(p.File), raw, chunkSize)
	if err != nil {
		return err
	}
	Client.SaveClient(cl)
	created, err := ft.XferCreate(ctx, uint64(len(cipher)), uint32(mf.ChunkSize), uint32(mf.ChunkCount), mf.Bytes(), mbox, pub, p.ShardURL)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	tid := created.TransferID
	for i, chunk := range chunks {
		h := sha256.Sum256(chunk)
		if _, err := ft.XferPut(ctx, tid, uint32(i), chunk, h[:], uint64(i*mf.ChunkSize)); err != nil {
			return fmt.Errorf("put %d: %w", i, err)
		}
	}
	cipherHash := sha256.Sum256(cipher)
	if err := ft.XferComplete(ctx, tid, cipherHash[:]); err != nil {
		return fmt.Errorf("complete: %w", err)
	}
	ticketRaw, err := filetransfer.MarshalTicket(&filetransfer.Ticket{
		Transfer: tid,
		Secret:   created.DownloadSecret,
		Shard:    created.ShardURL,
		Manifest: mf.Bytes(),
		From:     identity,
	})
	if err != nil {
		return err
	}
	ticketB64 := filetransfer.EncodeTicketString(ticketRaw)
	if d.Session != nil {
		d.Session.RecordTransfer(shellcmd.TransferRef{
			ID: hex.EncodeToString(tid), File: mf.FileName,
			Size: mf.PlainSize, TicketB64: ticketB64,
		})
	}
	if d.JSON {
		return d.JSONOut(map[string]any{
			"transfer_id": hex.EncodeToString(tid),
			"manifest":    base64.StdEncoding.EncodeToString(mf.Bytes()),
			"chunks":      len(chunks),
			"ticket":      ticketB64,
		})
	}
	d.Human("✓ Transfer created")
	d.Human("")
	d.Human("ID:")
	d.Human("%s", hex.EncodeToString(tid))
	d.Human("")
	d.Human("Ticket:")
	d.Human("%s", ticketB64)
	if desc, err := filetransfer.ParseTicket(ticketRaw); err == nil {
		d.Human("")
		d.Human("%s", desc.Describe())
	}
	d.Human("")
	d.Human("send the ticket to the recipient inside an E2E message; it carries the download secret")
	return nil
}

// XferRecvParams downloads via ticket or explicit mailbox credentials.
type XferRecvParams struct {
	TransportID string
	Identity    string // local peer ID; "" falls back to session identity
	Peer        string // expected sender; "" falls back to ticket From
	TicketB64   string // ticket mode (replaces transfer/mailbox/secret/manifest)
	TransferID  string // 32 hex (mailbox mode)
	MailboxID   string // 32 hex (mailbox mode)
	Secret      string // 64 hex bearer (mailbox mode; prompts hidden in shell)
	ShardURL    string // informational in mailbox mode
	ManifestB64 string // base64 manifest (mailbox mode)
	Out         string
}

// XferRecv downloads, verifies, reassembles and decrypts a transfer.
func XferRecv(d *Deps, p XferRecvParams) error {
	identity := p.Identity
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	ticketMode := p.TicketB64 != ""
	transferHex, mailboxHex, secretHex, shard, manifestB64 := p.TransferID, p.MailboxID, p.Secret, p.ShardURL, p.ManifestB64
	peer := p.Peer
	if ticketMode {
		ticketRaw, err := filetransfer.DecodeTicketString(p.TicketB64)
		if err != nil {
			return err
		}
		ticket, err := filetransfer.ParseTicket(ticketRaw)
		if err != nil {
			return err
		}
		transferHex = hex.EncodeToString(ticket.Transfer)
		manifestB64 = base64.StdEncoding.EncodeToString(ticket.Manifest)
		secretHex = hex.EncodeToString(ticket.Secret)
		shard = ticket.Shard
		mailboxHex = ""
		if peer == "" {
			peer = ticket.From
		}
	}
	if peer == "" {
		return fmt.Errorf("--from (expected sender) is required")
	}
	if p.Out == "" {
		return fmt.Errorf("--out is required")
	}
	if !ticketMode && (transferHex == "" || mailboxHex == "" || secretHex == "" || manifestB64 == "") {
		return fmt.Errorf("--transfer/--mailbox/--secret/--manifest are required without --ticket")
	}
	tid, err := hex.DecodeString(transferHex)
	if err != nil || len(tid) != 16 {
		return fmt.Errorf("transfer must be 32 hex chars")
	}
	secretHex, err = d.SecretOr(secretHex, "transfer secret (hidden): ")
	if err != nil {
		return err
	}
	var mbox, sec, ticket []byte
	if ticketMode {
		ticket, err = hex.DecodeString(secretHex)
		if err != nil || len(ticket) != 32 {
			return fmt.Errorf("ticket secret must be 64 hex chars")
		}
		if shard == "" {
			return fmt.Errorf("ticket shard missing")
		}
	} else {
		mbox, err = hex.DecodeString(mailboxHex)
		if err != nil || len(mbox) != 16 {
			return fmt.Errorf("mailbox must be 32 hex chars")
		}
		sec, err = hex.DecodeString(secretHex)
		if err != nil || len(sec) != 32 {
			return fmt.Errorf("secret must be 64 hex chars")
		}
	}
	mfRaw, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	mf, err := filetransfer.ParseManifest(mfRaw)
	if err != nil {
		return err
	}
	cl, err := Client.LoadClient(identity)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, p.TransportID)
	if err != nil {
		return err
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		return err
	}
	var highest uint32
	var missing [][2]uint32
	if ticketMode {
		_, highest, missing, err = ft.XferResumeByTicket(ctx, tid, ticket, shard)
	} else {
		_, highest, missing, err = ft.XferResume(ctx, tid, mbox, sec)
	}
	if err != nil {
		return fmt.Errorf("resume: %w", err)
	}
	if len(missing) > 0 {
		return fmt.Errorf("transfer incomplete (highest=%d, %d missing ranges); retry later", highest, len(missing))
	}
	chunks := make([][]byte, mf.ChunkCount)
	for i := 0; i < mf.ChunkCount; i++ {
		var payload, h []byte
		if ticketMode {
			payload, h, err = ft.XferGetByTicket(ctx, tid, uint32(i), ticket, shard)
		} else {
			payload, h, err = ft.XferGet(ctx, tid, uint32(i), mbox, sec)
		}
		if err != nil {
			return fmt.Errorf("get %d: %w", i, err)
		}
		if hh := sha256.Sum256(payload); hex.EncodeToString(hh[:]) != hex.EncodeToString(h) {
			return fmt.Errorf("chunk %d hash mismatch", i)
		}
		chunks[i] = payload
	}
	plain, err := filetransfer.ReassembleAndDecrypt(cl, peer, chunks, mf)
	if err != nil {
		return err
	}
	Client.SaveClient(cl)
	if err := os.WriteFile(p.Out, plain, 0o600); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"received_bytes": len(plain), "out": p.Out})
	}
	d.Human("Received %d bytes -> %s", len(plain), p.Out)
	return nil
}

// XferResumeParams reports transfer progress without downloading.
type XferResumeParams struct {
	TransportID string
	TransferID  string // 32 hex
	MailboxID   string // mailbox mode
	Secret      string // mailbox mode bearer
	TicketB64   string // ticket mode (replaces mailbox/secret)
	ShardURL    string // ticket mode shard
}

// XferResume shows highest-contiguous and missing ranges.
func XferResume(d *Deps, p XferResumeParams) error {
	var tid []byte
	if p.TicketB64 == "" {
		var err error
		tid, err = hex.DecodeString(p.TransferID)
		if err != nil || len(tid) != 16 {
			return fmt.Errorf("transfer must be 32 hex chars")
		}
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, p.TransportID)
	if err != nil {
		return err
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		return err
	}
	var count, highest uint32
	var missing [][2]uint32
	if p.TicketB64 != "" {
		ticketRaw, err := filetransfer.DecodeTicketString(p.TicketB64)
		if err != nil {
			return err
		}
		ticket, err := filetransfer.ParseTicket(ticketRaw)
		if err != nil {
			return err
		}
		shard := p.ShardURL
		if shard == "" {
			shard = ticket.Shard
		}
		count, highest, missing, err = ft.XferResumeByTicket(ctx, ticket.Transfer, ticket.Secret, shard)
		if err != nil {
			return fmt.Errorf("resume: %w", err)
		}
	} else {
		secretHex, err := d.SecretOr(p.Secret, "transfer secret (hidden): ")
		if err != nil {
			return err
		}
		mbox, err := hex.DecodeString(p.MailboxID)
		if err != nil || len(mbox) != 16 {
			return fmt.Errorf("mailbox must be 32 hex chars")
		}
		sec, err := hex.DecodeString(secretHex)
		if err != nil || len(sec) != 32 {
			return fmt.Errorf("secret must be 64 hex chars")
		}
		count, highest, missing, err = ft.XferResume(ctx, tid, mbox, sec)
		if err != nil {
			return fmt.Errorf("resume: %w", err)
		}
	}
	if d.JSON {
		return d.JSONOut(map[string]any{
			"transfer_id": p.TransferID, "chunk_count": count,
			"highest": highest, "missing": missing,
		})
	}
	if len(missing) == 0 {
		d.Human("Transfer %s complete: %d/%d chunks.", shortHex(p.TransferID), highest, count)
		return nil
	}
	d.Human("Transfer %s: highest contiguous %d/%d, %d missing range(s):",
		shortHex(p.TransferID), highest, count, len(missing))
	for _, r := range missing {
		d.Human("  chunks %d..%d", r[0], r[0]+r[1]-1)
	}
	return nil
}

// XferCancelParams aborts a transfer. Mailbox-owner auth only.
type XferCancelParams struct {
	TransportID string
	TransferID  string // 32 hex
	MailboxID   string // 32 hex
	Secret      string // 64 hex bearer
}

// XferCancel aborts a transfer after confirmation.
func XferCancel(d *Deps, p XferCancelParams) error {
	tid, err := hex.DecodeString(p.TransferID)
	if err != nil || len(tid) != 16 {
		return fmt.Errorf("transfer must be 32 hex chars")
	}
	mbox, err := hex.DecodeString(p.MailboxID)
	if err != nil || len(mbox) != 16 {
		return fmt.Errorf("mailbox must be 32 hex chars")
	}
	secretHex, err := d.SecretOr(p.Secret, "mailbox read secret (hidden): ")
	if err != nil {
		return err
	}
	sec, err := hex.DecodeString(secretHex)
	if err != nil || len(sec) != 32 {
		return fmt.Errorf("secret must be 64 hex chars")
	}
	ok, err := d.ConfirmOr(fmt.Sprintf("Cancel transfer %s? Recipients lose access.", shortHex(p.TransferID)))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted")
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, p.TransportID)
	if err != nil {
		return err
	}
	ft, err := ntx.RequiresFile(tr)
	if err != nil {
		return err
	}
	if err := ft.XferCancel(ctx, tid, mbox, sec); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"cancelled": shortHex(p.TransferID)})
	}
	d.Human("Transfer %s cancelled.", shortHex(p.TransferID))
	return nil
}

// XferInspect decodes a ticket (base64 NanoPack) with zero network I/O and
// describes the transfer it references.
func XferInspect(d *Deps, ticketB64 string) error {
	raw, err := filetransfer.DecodeTicketString(ticketB64)
	if err != nil {
		return err
	}
	ticket, err := filetransfer.ParseTicket(raw)
	if err != nil {
		return err
	}
	mf, err := filetransfer.ParseManifest(ticket.Manifest)
	if err != nil {
		return fmt.Errorf("embedded manifest: %w", err)
	}
	if d.JSON {
		return d.JSONOut(map[string]any{
			"transfer_id": hex.EncodeToString(ticket.Transfer),
			"shard_url":   ticket.Shard,
			"from":        ticket.From,
			"file":        mf.FileName,
			"plain_size":  mf.PlainSize,
			"chunks":      mf.ChunkCount,
			"secret":      d.Secret(hex.EncodeToString(ticket.Secret)),
		})
	}
	d.Human("Transfer %s", hex.EncodeToString(ticket.Transfer))
	d.Human("  file:     %s (%d bytes, %d chunks)", mf.FileName, mf.PlainSize, mf.ChunkCount)
	d.Human("  shard:    %s", ticket.Shard)
	if ticket.From != "" {
		d.Human("  from:     %s", ticket.From)
	}
	d.Human("  secret:   %s", d.Secret(hex.EncodeToString(ticket.Secret)))
	return nil
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
