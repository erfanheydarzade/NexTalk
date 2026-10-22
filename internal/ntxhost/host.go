package ntxhost

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// SpawnFunc instantiates a transport runtime from an already hash-verified
// .wasm module. Native tests pass transport.NewWASMTransport (wazero); the
// browser bridge passes a JS-WebAssembly-backed implementation.
type SpawnFunc func(ctx context.Context, wasm []byte, mf *transport.Manifest, cfg []byte) (transport.FrameTransport, error)

// Identity is the trusted per-call view of the active NexTalk identity.
type Identity struct {
	Client *client.Client
	Deps   *dispatch.Deps // Mailbox may be nil; Fanout may be nil (group msgs error)
	// Lock, if set, serialises dispatch against every other user of the same
	// Client (the bridge's relay.listen shares it).
	Lock sync.Locker
}

// IdentityFunc resolves the active identity, or errors when none is loaded.
type IdentityFunc func() (*Identity, error)

// Options configures a Host.
type Options struct {
	Spawn     SpawnFunc
	Identity  IdentityFunc
	Registrar Registrar // nil => RouterRegistrar()
}

// Host is the in-memory transport registry for one browser tab.
type Host struct {
	spawn     SpawnFunc
	ident     IdentityFunc
	registrar Registrar

	startMu sync.Mutex // serialises runtime start-up (spawn awaits JS)
	mu      sync.Mutex
	recs    map[string]*record
}

type record struct {
	pkg     *Package
	pinned  string
	enabled bool
	attach  []transport.Attachment
	live    transport.FrameTransport
}

// New builds an empty Host.
func New(o Options) *Host {
	r := o.Registrar
	if r == nil {
		r = RouterRegistrar()
	}
	return &Host{spawn: o.Spawn, ident: o.Identity, registrar: r, recs: map[string]*record{}}
}

// Info is the JS-visible description of an installed transport.
type Info struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Enabled      bool     `json:"enabled"`
	Capabilities []string `json:"capabilities"`
	Permissions  []string `json:"permissions"`
	Description  string   `json:"description"`
	Hash         string   `json:"hash"`
	Entry        string   `json:"entry"`
}

func infoOf(p *Package, enabled bool) Info {
	m := p.Manifest
	return Info{
		ID: m.ID, Name: m.Name, Version: m.Version, Enabled: enabled,
		Capabilities: nonNil(m.Capabilities), Permissions: nonNil(m.Permissions),
		Description: m.Description, Hash: p.Hash, Entry: m.Entry,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string(nil), s...)
}

// Install pins a package. It is DISABLED unless enable is true. Re-installing
// a different package under a live id is refused; an identical re-install
// keeps its state; a changed package resets to disabled (new hash, new trust
// decision). Attachments survive an update, as with the CLI manager.
func (h *Host) Install(raw []byte, enable bool) (*Info, error) {
	pkg, err := Inspect(raw)
	if err != nil {
		return nil, err
	}
	id := pkg.Manifest.ID
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, exists := h.recs[id]
	switch {
	case !exists:
		rec = &record{}
		h.recs[id] = rec
	case rec.live != nil:
		return nil, fmt.Errorf("ntxhost: %q is running; disable it first", id)
	case rec.pinned != pkg.Hash:
		rec.enabled = false
	}
	rec.pkg, rec.pinned = pkg, pkg.Hash
	if enable {
		if err := pkg.Verify(rec.pinned); err != nil {
			return nil, err
		}
		rec.enabled = true
	}
	info := infoOf(pkg, rec.enabled)
	return &info, nil
}

// List returns installed transports sorted by id.
func (h *Host) List() []Info {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Info, 0, len(h.recs))
	for _, r := range h.recs {
		out = append(out, infoOf(r.pkg, r.enabled))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Enable re-verifies the pinned hash, then marks the transport enabled. The
// runtime itself starts lazily on first use (and re-verifies again).
func (h *Host) Enable(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, ok := h.recs[id]
	if !ok {
		return fmt.Errorf("ntxhost: %q is not installed", id)
	}
	if err := rec.pkg.Verify(rec.pinned); err != nil {
		rec.enabled = false
		return err
	}
	rec.enabled = true
	return nil
}

// Disable stops a running transport and marks it disabled.
func (h *Host) Disable(ctx context.Context, id string) error {
	h.mu.Lock()
	rec, ok := h.recs[id]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("ntxhost: %q is not installed", id)
	}
	live := rec.live
	rec.live, rec.enabled = nil, false
	h.mu.Unlock()
	stopLive(ctx, live)
	return nil
}

// Remove stops the transport and deletes the package and its attachments.
func (h *Host) Remove(ctx context.Context, id string) error {
	h.mu.Lock()
	rec, ok := h.recs[id]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("ntxhost: %q is not installed", id)
	}
	live := rec.live
	delete(h.recs, id)
	h.mu.Unlock()
	stopLive(ctx, live)
	return nil
}

func stopLive(ctx context.Context, t transport.FrameTransport) {
	if t == nil {
		return
	}
	_ = t.Stop(ctx)
	if k, ok := t.(interface{ Kill() error }); ok {
		_ = k.Kill()
	}
}

// Status reports whether the runtime is live. It never starts anything.
func (h *Host) Status(ctx context.Context, id string) (running bool, detail string, err error) {
	h.mu.Lock()
	rec, ok := h.recs[id]
	var live transport.FrameTransport
	var enabled bool
	if ok {
		live, enabled = rec.live, rec.enabled
	}
	h.mu.Unlock()
	switch {
	case !ok:
		return false, "", fmt.Errorf("ntxhost: %q is not installed", id)
	case live != nil:
		return live.Status(ctx)
	case !enabled:
		return false, "disabled", nil
	}
	return false, "enabled, not started", nil
}

// ensure returns the live transport, starting it if it is enabled but not
// running: hash re-verified, capabilities cross-checked against the
// manifest, attachments replayed.
func (h *Host) ensure(ctx context.Context, id string) (transport.FrameTransport, *Package, error) {
	h.startMu.Lock()
	defer h.startMu.Unlock()

	h.mu.Lock()
	rec, ok := h.recs[id]
	if !ok {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("ntxhost: %q is not installed", id)
	}
	if !rec.enabled {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("ntxhost: %q is disabled (enable it first)", id)
	}
	if rec.live != nil {
		t, p := rec.live, rec.pkg
		h.mu.Unlock()
		return t, p, nil
	}
	pkg, pinned := rec.pkg, rec.pinned
	atts := append([]transport.Attachment(nil), rec.attach...)
	h.mu.Unlock()

	if h.spawn == nil {
		return nil, nil, fmt.Errorf("ntxhost: no WASM runtime configured")
	}
	if err := pkg.Verify(pinned); err != nil {
		return nil, nil, err
	}
	t, err := h.spawn(ctx, pkg.Entry, pkg.Manifest, nil)
	if err != nil {
		return nil, nil, err
	}
	// Fail closed: the module may not claim more than its manifest declared
	// (and so than the user saw at inspect/install time).
	for _, c := range t.Capabilities() {
		if !pkg.Manifest.HasCapability(c) {
			stopLive(ctx, t)
			return nil, nil, fmt.Errorf("ntxhost: %q module claims capability %q not declared in its manifest", id, c)
		}
	}
	if err := t.Start(ctx); err != nil {
		stopLive(ctx, t)
		return nil, nil, err
	}
	for _, a := range atts {
		mbox, sec, err := decodeAttachment(a)
		if err != nil {
			stopLive(ctx, t)
			return nil, nil, fmt.Errorf("ntxhost: %q has a corrupt attachment: %w", id, err)
		}
		if err := t.AttachMailbox(ctx, mbox, sec, a.ShardURL, a.RouterURL); err != nil {
			stopLive(ctx, t)
			return nil, nil, fmt.Errorf("ntxhost: %q replay attach %s: %w", id, short(a.MailboxID), err)
		}
	}
	h.mu.Lock()
	rec2, still := h.recs[id]
	if !still || rec2 != rec || !rec.enabled {
		h.mu.Unlock()
		stopLive(ctx, t)
		return nil, nil, fmt.Errorf("ntxhost: %q changed while starting", id)
	}
	rec.live = t
	h.mu.Unlock()
	return t, pkg, nil
}

func decodeAttachment(a transport.Attachment) (mbox, sec []byte, err error) {
	if len(a.MailboxID) != 32 || !isHex(a.MailboxID) {
		return nil, nil, fmt.Errorf("mailbox_id must be 32 hex chars")
	}
	if len(a.ReadSecret) != 64 || !isHex(a.ReadSecret) {
		return nil, nil, fmt.Errorf("read_secret must be 64 hex chars")
	}
	mbox, _ = hex.DecodeString(a.MailboxID)
	sec, _ = hex.DecodeString(a.ReadSecret)
	return mbox, sec, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func (h *Host) identity() (*Identity, error) {
	if h.ident == nil {
		return nil, fmt.Errorf("ntxhost: no identity provider")
	}
	id, err := h.ident()
	if err != nil {
		return nil, err
	}
	if id == nil || id.Client == nil || id.Client.Id == "" {
		return nil, fmt.Errorf("no identity loaded — call NexTalk.init() first")
	}
	return id, nil
}
