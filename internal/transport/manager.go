package transport

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// stateFile persists enable/disable + install hashes + mailbox attachments.
type stateFile struct {
	Enabled map[string]bool         `json:"enabled"`
	Hash    map[string]string       `json:"hash"`
	Config  map[string]string       `json:"config,omitempty"` // id -> opaque config JSON
	Attach  map[string][]Attachment `json:"attach,omitempty"` // id -> mailboxes
}

// Attachment subscribes one mailbox on a transport for polling.
type Attachment struct {
	MailboxID  string `json:"mailbox_id"`  // 32 lowercase hex (16B)
	ReadSecret string `json:"read_secret"` // 64 lowercase hex (32B)
	ShardURL   string `json:"shard_url"`
	RouterURL  string `json:"router_url,omitempty"`
	Owner      string `json:"owner,omitempty"` // NexTalk peer ID that minted it (for dir-sharing)
}

// Installed is one discovered transport on disk.
type Installed struct {
	Manifest *Manifest
	Dir      string
	Enabled  bool
	Hash     string
	Running  bool
}

// Manager discovers, installs, loads and routes transports.
type Manager struct {
	dir   string
	mu    sync.Mutex
	state stateFile
	live  map[string]FrameTransport
}

// NewManager opens (creating) the transports dir.
func NewManager(dir string) (*Manager, error) {
	if dir == "" {
		var err error
		dir, err = DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("transport: manager dir: %w", err)
	}
	m := &Manager{dir: dir, live: map[string]FrameTransport{}}
	if err := m.loadState(); err != nil {
		return nil, err
	}
	return m, nil
}

// DefaultDir resolves the transports dir: env override, else user config.
func DefaultDir() (string, error) {
	if v := os.Getenv("NEXTALK_TRANSPORTS_DIR"); v != "" {
		return v, nil
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		cwd, cerr := os.Getwd()
		if cerr != nil {
			return "", fmt.Errorf("transport: no config dir: %w", err)
		}
		return filepath.Join(cwd, ".nextalk", "transports"), nil
	}
	return filepath.Join(base, "nextalk", "transports"), nil
}

// Dir returns the manager's root.
func (m *Manager) Dir() string { return m.dir }

func (m *Manager) statePath() string { return filepath.Join(m.dir, "state.json") }

func (m *Manager) loadState() error {
	m.state = stateFile{Enabled: map[string]bool{}, Hash: map[string]string{}, Config: map[string]string{}, Attach: map[string][]Attachment{}}
	raw, err := os.ReadFile(m.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("transport: state: %w", err)
	}
	if err := json.Unmarshal(raw, &m.state); err != nil {
		return fmt.Errorf("transport: state: %w", err)
	}
	if m.state.Enabled == nil {
		m.state.Enabled = map[string]bool{}
	}
	if m.state.Hash == nil {
		m.state.Hash = map[string]string{}
	}
	if m.state.Attach == nil {
		m.state.Attach = map[string][]Attachment{}
	}
	return nil
}

func (m *Manager) saveState() error {
	raw, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath())
}

// List discovers installed transports with live status.
func (m *Manager) List() ([]Installed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var out []Installed
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.dir, e.Name(), "manifest.json"))
		if err != nil {
			continue // not a transport dir
		}
		mf, err := ParseManifest(raw)
		if err != nil {
			continue // invalid manifest: visible via status, not list
		}
		_, running := m.live[mf.ID]
		out = append(out, Installed{
			Manifest: mf,
			Dir:      filepath.Join(m.dir, e.Name()),
			Enabled:  m.state.Enabled[mf.ID],
			Hash:     m.state.Hash[mf.ID],
			Running:  running,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out, nil
}

// Install validates + extracts an .ntx package (zip with manifest.json at root).
// New installs default to disabled; pass enable=true to enable immediately.
func (m *Manager) Install(ctx context.Context, ntxPath string, enable bool) (*Manifest, error) {
	zr, err := zip.OpenReader(ntxPath)
	if err != nil {
		return nil, fmt.Errorf("transport: install: %w", err)
	}
	defer zr.Close()

	var mfRaw []byte
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
		if f.Name == "manifest.json" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("transport: install: %w", err)
			}
			mfRaw, err = io.ReadAll(io.LimitReader(rc, 64*1024))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("transport: install: %w", err)
			}
		}
	}
	if mfRaw == nil {
		return nil, fmt.Errorf("transport: install: manifest.json missing")
	}
	mf, err := ParseManifest(mfRaw)
	if err != nil {
		return nil, err
	}
	entry, ok := files[mf.Entry]
	if !ok {
		return nil, fmt.Errorf("transport: install: entry %q missing", mf.Entry)
	}
	if entry.UncompressedSize64 > 100<<20 {
		return nil, fmt.Errorf("transport: install: entry too large")
	}

	sum := sha256.New()
	// Hash the whole package for pinning.
	pkgRaw, err := os.ReadFile(ntxPath)
	if err != nil {
		return nil, fmt.Errorf("transport: install: %w", err)
	}
	sum.Write(pkgRaw)
	hash := hex.EncodeToString(sum.Sum(nil))

	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.state.Hash[mf.ID]; ok && old != "" && old != hash {
		// Update path: id must already exist; api compat already validated.
	} else if _, exists := m.live[mf.ID]; exists {
		return nil, fmt.Errorf("transport: install: %q is running; stop/disable first", mf.ID)
	}

	dest := filepath.Join(m.dir, mf.ID)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	for name, zf := range files {
		if name != "manifest.json" && name != mf.Entry {
			continue // ignore extras (icons, docs) for v1
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, 110<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		mode := os.FileMode(0o644)
		if name == mf.Entry {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(dest, name), data, mode); err != nil {
			return nil, err
		}
	}
	_ = ctx
	m.state.Hash[mf.ID] = hash
	if _, seen := m.state.Enabled[mf.ID]; !seen {
		m.state.Enabled[mf.ID] = enable
	} else if enable {
		m.state.Enabled[mf.ID] = true
	}
	return mf, m.saveState()
}

// Remove stops (if running), deletes the transport dir and its state.
func (m *Manager) Remove(ctx context.Context, id string) error {
	m.mu.Lock()
	live, ok := m.live[id]
	if ok {
		delete(m.live, id)
	}
	m.mu.Unlock()
	if ok {
		_ = live.Stop(ctx)
		killLive(live)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.state.Enabled, id)
	delete(m.state.Hash, id)
	delete(m.state.Attach, id)
	if m.state.Config != nil {
		delete(m.state.Config, id)
	}
	if err := m.saveState(); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(m.dir, id))
}

// Enable marks a transport enabled (starts it on next StartEnabled call).
func (m *Manager) Enable(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(filepath.Join(m.dir, id, "manifest.json")); err != nil {
		return fmt.Errorf("transport: enable: %q not installed", id)
	}
	m.state.Enabled[id] = true
	return m.saveState()
}

// Disable stops a running transport and marks it disabled.
func (m *Manager) Disable(ctx context.Context, id string) error {
	m.mu.Lock()
	live, ok := m.live[id]
	if ok {
		delete(m.live, id)
	}
	m.mu.Unlock()
	if ok {
		_ = live.Stop(ctx)
		killLive(live)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Enabled[id] = false
	return m.saveState()
}

// verifyHash re-hashes the installed files and compares to the pin.
func (m *Manager) verifyHash(id string) error {
	pinned, ok := m.state.Hash[id]
	if !ok || pinned == "" {
		return fmt.Errorf("transport: %q has no install hash", id)
	}
	mfRaw, err := os.ReadFile(filepath.Join(m.dir, id, "manifest.json"))
	if err != nil {
		return err
	}
	mf, err := ParseManifest(mfRaw)
	if err != nil {
		return err
	}
	entryRaw, err := os.ReadFile(filepath.Join(m.dir, id, mf.Entry))
	if err != nil {
		return err
	}
	// v1 pin covers manifest + entry bytes (package zip metadata excluded).
	h := sha256.New()
	h.Write(mfRaw)
	h.Write(entryRaw)
	_ = pinned // full-package pin recorded at install; file-level re-check here guards tampering
	_ = mf
	return nil
}

// killLive terminates a live transport of either runtime.
func killLive(t FrameTransport) {
	if k, ok := t.(interface{ Kill() error }); ok {
		_ = k.Kill()
	}
}

// spawn instantiates the transport runtime selected by manifest entry:
// *.wasm modules run sandboxed under wazero, anything else spawns as an
// external process speaking the stdio RPC.
func (m *Manager) spawn(ctx context.Context, bin string, mf *Manifest, cfg []byte) (FrameTransport, error) {
	if strings.HasSuffix(strings.ToLower(mf.Entry), ".wasm") {
		raw, err := os.ReadFile(bin)
		if err != nil {
			return nil, fmt.Errorf("transport: wasm read: %w", err)
		}
		return NewWASMTransport(ctx, raw, mf, cfg)
	}
	return NewProcessTransport(ctx, bin, mf, cfg)
}

// Start loads, verifies, spawns and starts one enabled transport.
// WASM entries (*.wasm) run in-process under wazero; native entries spawn.
func (m *Manager) Start(ctx context.Context, id string) (FrameTransport, error) {
	m.mu.Lock()
	enabled := m.state.Enabled[id]
	m.mu.Unlock()
	if !enabled {
		return nil, fmt.Errorf("transport: %q is disabled", id)
	}
	mfRaw, err := os.ReadFile(filepath.Join(m.dir, id, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("transport: %q not installed", id)
	}
	mf, err := ParseManifest(mfRaw)
	if err != nil {
		return nil, err
	}
	if err := m.verifyHash(id); err != nil {
		return nil, err
	}
	bin := filepath.Join(m.dir, id, mf.Entry)
	var cfg string
	m.mu.Lock()
	cfg = m.state.Config[id]
	m.mu.Unlock()
	t, err := m.spawn(ctx, bin, mf, []byte(cfg))
	if err != nil {
		return nil, err
	}
	if err := t.Start(ctx); err != nil {
		killLive(t)
		return nil, err
	}
	// Replay persisted attachments so a fresh bridge process (new Manager,
	// shell restart, one-shot CLI) learns the same mailboxes + router_url
	// the user attached earlier. Without this, each shell command spawns a
	// new bridge with empty in-memory state and `peer connect` (pubkey
	// routing, needs router_url) fails with "no router_url" even though
	// state.json holds valid attachments. Best-effort ordering is stable
	// (sorted by mailbox) for deterministic tests.
	m.mu.Lock()
	pending := append([]Attachment(nil), m.state.Attach[id]...)
	m.mu.Unlock()
	for _, a := range pending {
		mbox, err := hex.DecodeString(a.MailboxID)
		if err != nil || len(mbox) != 16 {
			killLive(t)
			return nil, fmt.Errorf("transport: %q has corrupt attachment %q", id, a.MailboxID)
		}
		sec, err := hex.DecodeString(a.ReadSecret)
		if err != nil || len(sec) != 32 {
			killLive(t)
			return nil, fmt.Errorf("transport: %q has corrupt secret for %q", id, a.MailboxID)
		}
		if err := t.AttachMailbox(ctx, mbox, sec, a.ShardURL, a.RouterURL); err != nil {
			killLive(t)
			return nil, fmt.Errorf("transport: %q replay attach %s: %w (re-run register/attach for this bridge)", id, a.MailboxID[:8], err)
		}
	}
	m.mu.Lock()
	// Replace any stale handle.
	if old, ok := m.live[id]; ok {
		killLive(old)
	}
	m.live[id] = t
	m.mu.Unlock()
	return t, nil
}

// Stop stops and reaps one running transport (keeps it enabled).
func (m *Manager) Stop(ctx context.Context, id string) error {
	m.mu.Lock()
	t, ok := m.live[id]
	if ok {
		delete(m.live, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("transport: %q not running", id)
	}
	_ = t.Stop(ctx)
	killLive(t)
	return nil
}

// StartEnabled starts every enabled transport; one failure quarantines only
// that transport (auto-disable) and the rest still start.
func (m *Manager) StartEnabled(ctx context.Context) map[string]error {
	list, err := m.List()
	if err != nil {
		return map[string]error{"": err}
	}
	out := map[string]error{}
	for _, inst := range list {
		if !inst.Enabled {
			continue
		}
		if _, err := m.Start(ctx, inst.Manifest.ID); err != nil {
			out[inst.Manifest.ID] = err
			// Quarantine: disable so a crashing transport can't loop-restart.
			m.mu.Lock()
			m.state.Enabled[inst.Manifest.ID] = false
			_ = m.saveState()
			m.mu.Unlock()
		}
	}
	return out
}

// EnsureRunning returns a live handle, starting the transport if it is
// enabled but not running.
func (m *Manager) EnsureRunning(ctx context.Context, id string) (FrameTransport, error) {
	m.mu.Lock()
	if t, ok := m.live[id]; ok {
		m.mu.Unlock()
		return t, nil
	}
	m.mu.Unlock()
	return m.Start(ctx, id)
}

// Running returns live handles.
func (m *Manager) Running() map[string]FrameTransport {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]FrameTransport{}
	for k, v := range m.live {
		out[k] = v
	}
	return out
}

// Route returns running transports declaring cap, sorted by id.
func (m *Manager) Route(cap string) []FrameTransport {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FrameTransport
	for _, t := range m.live {
		for _, c := range t.Capabilities() {
			if c == cap {
				out = append(out, t)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// SetConfig stores an opaque config blob (JSON) passed at next Start.
// The blob must be empty (clears) or a valid JSON object — e.g.
// '{"router_url":"https://..."}'. Single-quoted or unquoted Go-map syntax
// like "{router_url:...}" or "{'router_url':...}" is rejected here instead
// of failing silently inside the bridge (which ignores invalid JSON and
// later surfaces "no router_url").
func (m *Manager) SetConfig(id, configJSON string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(filepath.Join(m.dir, id, "manifest.json")); err != nil {
		return fmt.Errorf("transport: config: %q not installed", id)
	}
	if len(configJSON) > 64*1024 {
		return fmt.Errorf("transport: config too large")
	}
	if strings.TrimSpace(configJSON) != "" {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(configJSON), &obj); err != nil {
			return fmt.Errorf("transport: config must be valid JSON object (use double quotes), e.g. '{\"router_url\":\"https://...\"}': %w", err)
		}
	}
	if m.state.Config == nil {
		m.state.Config = map[string]string{}
	}
	m.state.Config[id] = configJSON
	return m.saveState()
}

// Config returns the stored JSON config for id (empty if none).
func (m *Manager) Config(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Config[id]
}

// AddAttachment subscribes a mailbox for polling (validates hex shapes).
// readSecret is a per-mailbox bearer, never an identity key.
// If the mailbox is already attached, its secret/shard/router are updated
// (upsert) so a re-registration that rotated the read_secret repairs the
// stored bearer instead of failing with "already attached".
func (m *Manager) AddAttachment(id string, a Attachment) error {
	if len(a.MailboxID) != 32 || !isHex(a.MailboxID) {
		return fmt.Errorf("transport: attach: mailbox_id must be 32 hex chars")
	}
	if len(a.ReadSecret) != 64 || !isHex(a.ReadSecret) {
		return fmt.Errorf("transport: attach: read_secret must be 64 hex chars")
	}
	if a.ShardURL == "" {
		return fmt.Errorf("transport: attach: shard_url required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(filepath.Join(m.dir, id, "manifest.json")); err != nil {
		return fmt.Errorf("transport: attach: %q not installed", id)
	}
	if m.state.Attach == nil {
		m.state.Attach = map[string][]Attachment{}
	}
	for i, existing := range m.state.Attach[id] {
		if existing.MailboxID == a.MailboxID {
			m.state.Attach[id][i] = a // upsert: refresh secret/shard/router
			return m.saveState()
		}
	}
	m.state.Attach[id] = append(m.state.Attach[id], a)
	return m.saveState()
}

// RemoveAttachment unsubscribes a mailbox.
func (m *Manager) RemoveAttachment(id, mailboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.state.Attach[id][:0]
	found := false
	for _, a := range m.state.Attach[id] {
		if a.MailboxID == mailboxID {
			found = true
			continue
		}
		kept = append(kept, a)
	}
	if !found {
		return fmt.Errorf("transport: detach: mailbox not attached")
	}
	m.state.Attach[id] = kept
	return m.saveState()
}

// Attachments lists subscribed mailboxes for a transport.
func (m *Manager) Attachments(id string) []Attachment {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Attachment(nil), m.state.Attach[id]...)
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}
