// Package filetransfer implements NexTalk's file-transfer cryptography.
//
// Decision (whole-file-before-chunking): the complete file is encrypted with
// the peer's 1:1 session (the same E2E primitive as messages), then the
// ciphertext is split into opaque chunks for the transport. The relay only
// ever sees ciphertext chunks. Per-chunk independent encryption is left for
// a future streaming construction; whole-file keeps the security argument
// identical to messaging (one session, one ratchet step, one HMAC).
//
// Limits: plaintext capped at MaxFilePlaintext (8 MiB) — session Encrypt is
// one-shot and memory-bound. Larger files need the future streaming
// construction.
package filetransfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/nanopack"
)

// MaxFilePlaintext caps file plaintext (8 MiB).
const MaxFilePlaintext = 8 << 20

// DefaultChunkSize is the ciphertext chunk size (matches relay ceilings).
const DefaultChunkSize = 32 * 1024

// ManifestSchemaID is the NanoPack schema for the file manifest.
// Registered in docs/serialization.md; never renumber.
const ManifestSchemaID byte = 12

// Manifest describes one encrypted file. It is a core-side artifact: the
// sender hands it to the recipient out-of-band (embedded in the transfer
// ticket). The transport only sees opaque chunks + this manifest blob.
//
// Wire form is NanoPack (schema 12): 1=file_name, 2=plain_size u64,
// 3=cipher_size u64, 4=chunk_size u32, 5=chunk_count u32, 6=file_hash 32B
// raw, 7=cipher_hash 32B raw. Hashes travel as raw bytes, never hex.
type Manifest struct {
	FileName   string
	PlainSize  int
	CipherSize int
	ChunkSize  int
	ChunkCount int
	FileHash   []byte // 32B raw sha256(plaintext)
	CipherHash []byte // 32B raw sha256(ciphertext)
}

// Bytes encodes the manifest to NanoPack for transport.
func (m *Manifest) Bytes() []byte {
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte(m.FileName))
	enc.AddID(2, putU64(uint64(m.PlainSize)))
	enc.AddID(3, putU64(uint64(m.CipherSize)))
	enc.AddID(4, putU32(uint32(m.ChunkSize)))
	enc.AddID(5, putU32(uint32(m.ChunkCount)))
	enc.AddID(6, m.FileHash)
	enc.AddID(7, m.CipherHash)
	raw, _ := enc.Bytes()
	return raw
}

// ParseManifest decodes + validates manifest bytes.
func ParseManifest(raw []byte) (*Manifest, error) {
	fields, err := nanopack.DecodeID(raw)
	if err != nil {
		return nil, fmt.Errorf("filetransfer: manifest: %w", err)
	}
	var m Manifest
	for _, f := range fields {
		switch f.ID {
		case 1:
			m.FileName = string(append([]byte(nil), f.Data...))
		case 2:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, fmt.Errorf("filetransfer: manifest: %w", err)
			}
			m.PlainSize = int(v)
		case 3:
			v, err := getU64(f.Data)
			if err != nil {
				return nil, fmt.Errorf("filetransfer: manifest: %w", err)
			}
			m.CipherSize = int(v)
		case 4:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, fmt.Errorf("filetransfer: manifest: %w", err)
			}
			m.ChunkSize = int(v)
		case 5:
			v, err := getU32(f.Data)
			if err != nil {
				return nil, fmt.Errorf("filetransfer: manifest: %w", err)
			}
			m.ChunkCount = int(v)
		case 6:
			m.FileHash = append([]byte(nil), f.Data...)
		case 7:
			m.CipherHash = append([]byte(nil), f.Data...)
		}
	}
	if m.ChunkCount <= 0 || m.ChunkSize <= 0 || m.CipherSize <= 0 ||
		len(m.FileHash) != 32 || len(m.CipherHash) != 32 {
		return nil, fmt.Errorf("filetransfer: manifest: bad sizes or hashes")
	}
	return &m, nil
}

// Describe renders a manifest for humans (display only, never parsed).
func (m *Manifest) Describe() string {
	return fmt.Sprintf("file %q: %d plaintext bytes in %d chunks of %d (sha256 %.12x)",
		m.FileName, m.PlainSize, m.ChunkCount, m.ChunkSize, m.FileHash)
}

func putU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	out := make([]byte, 4)
	copy(out, b[:])
	return out
}

func putU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	out := make([]byte, 8)
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

// EncryptFile encrypts plaintext for peerID and splits the ciphertext.
func EncryptFile(cl *Client.Client, peerID string, fileName string, plaintext []byte, chunkSize int) (cipher []byte, chunks [][]byte, mf *Manifest, err error) {
	if len(plaintext) == 0 || len(plaintext) > MaxFilePlaintext {
		return nil, nil, nil, fmt.Errorf("filetransfer: file size out of bounds (%d)", len(plaintext))
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize > 64*1024 {
		return nil, nil, nil, fmt.Errorf("filetransfer: chunk size out of bounds")
	}
	cipher, err = cl.Encrypt(peerID, plaintext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("filetransfer: encrypt: %w", err)
	}
	for off := 0; off < len(cipher); off += chunkSize {
		end := off + chunkSize
		if end > len(cipher) {
			end = len(cipher)
		}
		chunks = append(chunks, cipher[off:end])
	}
	fh := sha256.Sum256(plaintext)
	ch := sha256.Sum256(cipher)
	mf = &Manifest{
		FileName:   fileName,
		PlainSize:  len(plaintext),
		CipherSize: len(cipher),
		ChunkSize:  chunkSize,
		ChunkCount: len(chunks),
		FileHash:   append([]byte(nil), fh[:]...),
		CipherHash: append([]byte(nil), ch[:]...),
	}
	return cipher, chunks, mf, nil
}

// decryptFor unwraps Decrypt's (sender, plain, err) order for callers.
func decryptFor(cl *Client.Client, cipher []byte) (plain []byte, sender string, err error) {
	sender, plain, err = cl.Decrypt(cipher)
	return plain, sender, err
}

func shortPeer(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:6] + "..." + id[len(id)-4:]
}
// ReassembleAndDecrypt verifies chunk hashes, reassembles, and decrypts.
func ReassembleAndDecrypt(cl *Client.Client, peerID string, chunks [][]byte, mf *Manifest) ([]byte, error) {
	if len(chunks) != mf.ChunkCount {
		return nil, fmt.Errorf("filetransfer: want %d chunks, have %d", mf.ChunkCount, len(chunks))
	}
	var cipher []byte
	for i, c := range chunks {
		if len(c) == 0 {
			return nil, fmt.Errorf("filetransfer: chunk %d empty", i)
		}
		cipher = append(cipher, c...)
	}
	if len(cipher) != mf.CipherSize {
		return nil, fmt.Errorf("filetransfer: cipher size mismatch")
	}
	if ch := sha256.Sum256(cipher); !bytes.Equal(ch[:], mf.CipherHash) {
		return nil, fmt.Errorf("filetransfer: cipher hash mismatch (corrupt relay data)")
	}
	plaintext, senderID, err := decryptFor(cl, cipher)
	if err != nil {
		return nil, fmt.Errorf("filetransfer: decrypt: %w", err)
	}
	if peerID != "" && senderID != peerID {
		return nil, fmt.Errorf("filetransfer: sender mismatch (want %s, got %s)", shortPeer(peerID), shortPeer(senderID))
	}
	if len(plaintext) != mf.PlainSize {
		return nil, fmt.Errorf("filetransfer: plain size mismatch")
	}
	if fh := sha256.Sum256(plaintext); !bytes.Equal(fh[:], mf.FileHash) {
		return nil, fmt.Errorf("filetransfer: file hash mismatch")
	}
	return plaintext, nil
}
