package ntxhost

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// minimalWasm is a valid WebAssembly header: enough for Inspect, which only
// checks the magic. Runtimes in these tests are fakes, never this module.
var minimalWasm = []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}

func manifestJSON(id, entry string, caps ...string) string {
	cs := ""
	for i, c := range caps {
		if i > 0 {
			cs += ","
		}
		cs += fmt.Sprintf("%q", c)
	}
	return fmt.Sprintf(`{"id":%q,"name":"Test %s","version":"0.0.1","api_version":"1","entry":%q,"capabilities":[%s],"permissions":[]}`, id, id, entry, cs)
}

// makeNTX builds a .ntx package in memory.
func makeNTX(t testing.TB, manifest, entryName string, entry []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("manifest.json")
	_, _ = w.Write([]byte(manifest))
	w, _ = zw.Create(entryName)
	_, _ = w.Write(entry)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newClient(t testing.TB) *client.Client {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dp, dpub := crypto.GenerateDilithiumKeyPair()
	return client.NewClientFromKeys(crypto.DerivePeerID(pub, dpub), priv, pub, dp, dpub, make(map[string]*crypto.SecurePeer))
}

// pair returns two clients with an established session (in memory only:
// NewClientFromKeys clients never touch the filesystem).
func pair(t testing.TB) (a, b *client.Client) {
	t.Helper()
	a, b = newClient(t), newClient(t)
	offer, err := a.CreateOffer(b.Id)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := b.AcceptOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.FinishHandshake(answer); err != nil {
		t.Fatal(err)
	}
	return a, b
}

// who lets one Host act as either identity, like swapping importIdentity().
type who struct {
	mu  sync.Mutex
	cur *client.Client
}

func (w *who) set(c *client.Client) { w.mu.Lock(); w.cur = c; w.mu.Unlock() }
func (w *who) fn() (*Identity, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil {
		return nil, fmt.Errorf("no identity loaded")
	}
	return &Identity{Client: w.cur, Deps: &dispatch.Deps{Client: w.cur}}, nil
}

// ── fake registrar ────────────────────────────────────────────────────────

type fakeRegistrar struct{ calls int }

func (f *fakeRegistrar) Register(ctx context.Context, router string, priv ed25519.PrivateKey) (Capability, error) {
	f.calls++
	return Capability{
		MailboxID:  "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
		ReadSecret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		ShardURL:   "https://shard.test",
	}, nil
}
func (f *fakeRegistrar) Resolve(ctx context.Context, router, pubHex string) (Resolution, error) {
	return Resolution{MailboxID: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", ShardURL: "https://shard.test"}, nil
}

// ── fake runtimes ─────────────────────────────────────────────────────────

type memQueue struct {
	mu     sync.Mutex
	frames [][]byte
}

// memTransport is a FrameTransport over a shared FIFO (queue-model, like the
// hand-assembled module: recipient/mailbox routing is ignored).
type memTransport struct {
	id      string
	caps    []string
	q       *memQueue
	mu      sync.Mutex
	started bool
	killed  bool
}

func (m *memTransport) ID() string             { return m.id }
func (m *memTransport) Capabilities() []string { return m.caps }
func (m *memTransport) Start(context.Context) error {
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	return nil
}
func (m *memTransport) Stop(context.Context) error {
	m.mu.Lock()
	m.started = false
	m.mu.Unlock()
	return nil
}
func (m *memTransport) Kill() error { m.mu.Lock(); m.killed = true; m.mu.Unlock(); return nil }
func (m *memTransport) ok() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return &transport.RPCError{Code: transport.ErrNotReady, Detail: "transport not started"}
	}
	return nil
}
func (m *memTransport) SendFrame(_ context.Context, f transport.Frame, _ transport.RouteHint) error {
	if err := m.ok(); err != nil {
		return err
	}
	m.q.mu.Lock()
	m.q.frames = append(m.q.frames, append([]byte(nil), f...))
	m.q.mu.Unlock()
	return nil
}
func (m *memTransport) AttachMailbox(context.Context, []byte, []byte, string, string) error {
	return m.ok()
}
func (m *memTransport) DetachMailbox(context.Context, []byte) error { return m.ok() }
func (m *memTransport) PollFrames(_ context.Context, limit int, _ []byte) ([][]byte, error) {
	if err := m.ok(); err != nil {
		return nil, err
	}
	m.q.mu.Lock()
	defer m.q.mu.Unlock()
	n := len(m.q.frames)
	if limit > 0 && n > limit {
		n = limit
	}
	out := m.q.frames[:n:n]
	m.q.frames = append([][]byte(nil), m.q.frames[n:]...)
	return out, nil
}
func (m *memTransport) Status(context.Context) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started, "mem", nil
}

func memSpawn(q *memQueue) SpawnFunc {
	return func(_ context.Context, _ []byte, mf *transport.Manifest, _ []byte) (transport.FrameTransport, error) {
		return &memTransport{id: mf.ID, caps: append([]string(nil), mf.Capabilities...), q: q}, nil
	}
}

// fileStore + fileMem: a fake "binary-transfer" runtime (implements
// transport.FileTransport) holding transfers in memory.
type fileStore struct {
	mu     sync.Mutex
	n      int
	chunks map[string]map[uint32][]byte
	count  map[string]uint32
	secret map[string][]byte
}

func newFileStore() *fileStore {
	return &fileStore{chunks: map[string]map[uint32][]byte{}, count: map[string]uint32{}, secret: map[string][]byte{}}
}

type fileMem struct {
	*memTransport
	fs *fileStore
}

func (f *fileMem) XferCreate(_ context.Context, total uint64, chunkSize, chunkCount uint32, manifest, mailboxID, recipientPub []byte, shardURL string) (*transport.XferCreated, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	f.fs.n++
	tid := bytes.Repeat([]byte{byte(f.fs.n)}, 16)
	sec := bytes.Repeat([]byte{0x5e}, 32)
	f.fs.chunks[string(tid)] = map[uint32][]byte{}
	f.fs.count[string(tid)] = chunkCount
	f.fs.secret[string(tid)] = sec
	return &transport.XferCreated{TransferID: tid, Expires: 1234, DownloadSecret: sec, ShardURL: "https://shard.test"}, nil
}
func (f *fileMem) XferPut(_ context.Context, tid []byte, index uint32, payload, hash []byte, _ uint64) (uint32, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if sum := sha256.Sum256(payload); !bytes.Equal(sum[:], hash) {
		return 0, fmt.Errorf("put hash mismatch")
	}
	f.fs.chunks[string(tid)][index] = append([]byte(nil), payload...)
	return index + 1, nil
}
func (f *fileMem) XferComplete(context.Context, []byte, []byte) error { return nil }
func (f *fileMem) XferResumeByTicket(_ context.Context, tid, ticket []byte, _ string) (uint32, uint32, [][2]uint32, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if !bytes.Equal(f.fs.secret[string(tid)], ticket) {
		return 0, 0, nil, fmt.Errorf("bad ticket")
	}
	have := uint32(len(f.fs.chunks[string(tid)]))
	var missing [][2]uint32
	if have < f.fs.count[string(tid)] {
		missing = append(missing, [2]uint32{have, f.fs.count[string(tid)] - 1})
	}
	return have, have, missing, nil
}
func (f *fileMem) XferGetByTicket(_ context.Context, tid []byte, index uint32, ticket []byte, _ string) ([]byte, []byte, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if !bytes.Equal(f.fs.secret[string(tid)], ticket) {
		return nil, nil, fmt.Errorf("bad ticket")
	}
	p, ok := f.fs.chunks[string(tid)][index]
	if !ok {
		return nil, nil, fmt.Errorf("no chunk %d", index)
	}
	sum := sha256.Sum256(p)
	return p, sum[:], nil
}

// Unused by the bridge's ticket path; present to satisfy FileTransport.
func (f *fileMem) XferResume(context.Context, []byte, []byte, []byte) (uint32, uint32, [][2]uint32, error) {
	return 0, 0, nil, fmt.Errorf("unsupported")
}
func (f *fileMem) XferGet(context.Context, []byte, uint32, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("unsupported")
}
func (f *fileMem) XferCancel(context.Context, []byte, []byte, []byte) error { return nil }
func (f *fileMem) XferRegister(context.Context, string, string) ([]byte, []byte, string, string, error) {
	return nil, nil, "", "", fmt.Errorf("unsupported")
}
func (f *fileMem) IdentityRegister(context.Context, []byte, uint64, []byte, []byte, string) ([]byte, []byte, string, string, error) {
	return nil, nil, "", "", fmt.Errorf("unsupported")
}
func (f *fileMem) XferResolve(context.Context, []byte, string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("unsupported")
}

func fileSpawn(fs *fileStore, q *memQueue) SpawnFunc {
	return func(_ context.Context, _ []byte, mf *transport.Manifest, _ []byte) (transport.FrameTransport, error) {
		return &fileMem{memTransport: &memTransport{id: mf.ID, caps: append([]string(nil), mf.Capabilities...), q: q}, fs: fs}, nil
	}
}
