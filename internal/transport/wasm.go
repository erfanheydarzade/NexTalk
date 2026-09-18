// WASM transport runtime (wazero).
//
// A .wasm transport implements the function-call ABI below instead of the
// stdio RPC. Same trust model: opaque frames in, opaque frames out, no key
// material in the API. The sandbox is wazero (pure Go, no cgo): the module
// gets linear memory plus an optional ntx.log import and nothing else — no
// WASI, no sockets, no filesystem. Queue-model transports (local delivery,
// embedded demo) fit v1; transports needing sockets use the process model.
//
// ABI v1 (all integers little-endian wasm values; blobs are (ptr,len) pairs
// into the module's exported "memory"; data returns pack (ptr<<32|len) u64;
// the core copies results out immediately, so modules may reuse static
// out-regions):
//
//	ntx_init(cfg_ptr i32, cfg_len i32) -> i32            0 ok
//	ntx_caps() -> i64                                    CSV capabilities, e.g. "message"
//	ntx_start() -> i32, ntx_stop() -> i32                0 ok
//	ntx_send(frame_ptr, frame_len, recip_ptr, recip_len) -> i32
//	    0 ok, 1 not started, 2 bad args, 3 queue full
//	ntx_attach(mbox_ptr, sec_ptr, shard_ptr, shard_len, router_ptr, router_len) -> i32
//	    0 ok, 2 bad args (v1 queue transports may ignore shard/router URLs)
//	ntx_detach(mbox_ptr) -> i32                          0 ok
//	ntx_poll(limit i32, mbox_ptr i32, has_mbox i32) -> i64
//	    blob of BE32-len-prefixed full frames (drains); empty blob when none
//	ntx_status() -> i32                                  1 running, 0 stopped
//
// Frame size ceiling: 40 KiB (same as the process RPC).
package transport

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// WASMTransport adapts a .wasm module to FrameTransport.
type WASMTransport struct {
	manifest *Manifest
	runtime  wazero.Runtime
	mod      api.Module

	mu      sync.Mutex
	started bool
	caps    []string
	version string
	logs    []string
}

// NewWASMTransport instantiates moduleBytes and runs ntx_init.
func NewWASMTransport(ctx context.Context, moduleBytes []byte, m *Manifest, config []byte) (*WASMTransport, error) {
	rt := wazero.NewRuntime(ctx)
	t := &WASMTransport{manifest: m, runtime: rt, version: m.Version}
	// Optional host import: modules may import ntx.log, but must not require it.
	logFn := func(ptr, length uint32) {
		if mem := t.currentMemory(); mem != nil {
			if b, ok := mem.Read(ptr, length); ok && len(b) < 4096 {
				t.mu.Lock()
				t.logs = append(t.logs, string(b))
				t.mu.Unlock()
			}
		}
	}
	if _, err := rt.NewHostModuleBuilder("ntx").
		NewFunctionBuilder().WithFunc(logFn).Export("log").
		Instantiate(ctx); err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("transport: wasm host: %w", err)
	}
	compiled, err := rt.CompileModule(ctx, moduleBytes)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("transport: wasm compile: %w", err)
	}
	// Name the module after the transport id for diagnostics.
	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("ntx-"+m.ID))
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("transport: wasm instantiate %q: %w", m.ID, err)
	}
	t.mod = mod
	cfgPtr, err := t.writeMem(ctx, config)
	if err != nil {
		t.Close(ctx)
		return nil, err
	}
	rc, err := t.callU32(ctx, "ntx_init", cfgPtr, uint64(len(config)))
	if err != nil {
		t.Close(ctx)
		return nil, fmt.Errorf("transport: wasm %q ntx_init: %w", m.ID, err)
	}
	if rc != 0 {
		t.Close(ctx)
		return nil, fmt.Errorf("transport: wasm %q ntx_init refused: %d", m.ID, rc)
	}
	capsCSV, err := t.callBlob(ctx, "ntx_caps")
	if err != nil {
		t.Close(ctx)
		return nil, fmt.Errorf("transport: wasm %q ntx_caps: %w", m.ID, err)
	}
	for _, c := range strings.Split(string(capsCSV), ",") {
		if c = strings.TrimSpace(c); c != "" {
			if !KnownCapabilities[c] {
				t.Close(ctx)
				return nil, fmt.Errorf("transport: wasm %q unknown capability %q", m.ID, c)
			}
			t.caps = append(t.caps, c)
		}
	}
	if len(t.caps) == 0 {
		t.Close(ctx)
		return nil, fmt.Errorf("transport: wasm %q declares no capabilities", m.ID)
	}
	return t, nil
}

func (t *WASMTransport) currentMemory() api.Memory {
	if t.mod == nil {
		return nil
	}
	return t.mod.Memory()
}

// scratch region: ask the module for heap via exported ntx_alloc if present,
// else use a fixed high region (modules without alloc must reserve it).
func (t *WASMTransport) writeMem(ctx context.Context, data []byte) (uint64, error) {
	mem := t.currentMemory()
	if mem == nil {
		return 0, fmt.Errorf("transport: wasm: no memory")
	}
	if alloc := t.mod.ExportedFunction("ntx_alloc"); alloc != nil {
		res, err := alloc.Call(ctx, uint64(len(data)))
		if err != nil || len(res) != 1 {
			return 0, fmt.Errorf("transport: wasm ntx_alloc: %w", err)
		}
		ptr := uint32(res[0])
		if !mem.Write(ptr, data) {
			return 0, fmt.Errorf("transport: wasm: write out of bounds")
		}
		return uint64(ptr), nil
	}
	// Fallback scratch at 1 MiB; modules without ntx_alloc must keep it free.
	const scratch = 1 << 20
	if uint64(len(data)) > 1<<20 {
		return 0, fmt.Errorf("transport: wasm: arg too large")
	}
	if !mem.Write(scratch, data) {
		// Grow memory once and retry.
		if _, ok := mem.Grow(16); !ok {
			return 0, fmt.Errorf("transport: wasm grow failed")
		}
		if !mem.Write(scratch, data) {
			return 0, fmt.Errorf("transport: wasm: write out of bounds")
		}
	}
	return scratch, nil
}

func (t *WASMTransport) callU32(ctx context.Context, name string, args ...uint64) (uint32, error) {
	fn := t.mod.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("transport: wasm: missing export %q", name)
	}
	res, err := fn.Call(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("transport: wasm %s: %w", name, err)
	}
	if len(res) != 1 {
		return 0, fmt.Errorf("transport: wasm %s: bad result", name)
	}
	return uint32(res[0]), nil
}

// callBlob calls a () -> i64 function and copies the (ptr,len) region out.
func (t *WASMTransport) callBlob(ctx context.Context, name string, args ...uint64) ([]byte, error) {
	u, err := t.callU32x2(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	ptr := uint32(u >> 32)
	length := uint32(u)
	if length > MaxFrameBytes*33+16 {
		return nil, fmt.Errorf("transport: wasm %s: blob too large (%d)", name, length)
	}
	mem := t.currentMemory()
	b, ok := mem.Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("transport: wasm %s: blob out of bounds", name)
	}
	return append([]byte(nil), b...), nil
}

func (t *WASMTransport) callU32x2(ctx context.Context, name string, args ...uint64) (uint64, error) {
	fn := t.mod.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("transport: wasm: missing export %q", name)
	}
	res, err := fn.Call(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("transport: wasm %s: %w", name, err)
	}
	if len(res) != 1 {
		return 0, fmt.Errorf("transport: wasm %s: bad result", name)
	}
	return res[0], nil
}

// Logs returns captured ntx.log lines (diagnostics only).
func (t *WASMTransport) Logs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.logs...)
}

// Close terminates the runtime.
func (t *WASMTransport) Close(ctx context.Context) error {
	return t.runtime.Close(ctx)
}

// Kill force-terminates the runtime (manager quarantine path).
func (t *WASMTransport) Kill() error {
	return t.runtime.Close(context.Background())
}

// ID implements FrameTransport.
func (t *WASMTransport) ID() string { return t.manifest.ID }

// Capabilities implements FrameTransport.
func (t *WASMTransport) Capabilities() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.caps...)
}

// Version is the manifest version.
func (t *WASMTransport) Version() string { return t.version }

// Start implements FrameTransport.
func (t *WASMTransport) Start(ctx context.Context) error {
	rc, err := t.callU32(ctx, "ntx_start")
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("transport: wasm %q start refused: %d", t.manifest.ID, rc)
	}
	t.mu.Lock()
	t.started = true
	t.mu.Unlock()
	return nil
}

// Stop implements FrameTransport.
func (t *WASMTransport) Stop(ctx context.Context) error {
	rc, err := t.callU32(ctx, "ntx_stop")
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.started = false
	t.mu.Unlock()
	if rc != 0 {
		return fmt.Errorf("transport: wasm %q stop refused: %d", t.manifest.ID, rc)
	}
	return nil
}

func (t *WASMTransport) requireStarted() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started {
		return &RPCError{Code: ErrNotReady, Detail: "transport not started"}
	}
	return nil
}

// SendFrame implements FrameTransport (queue-model: explicit mailbox/shard
// routing is ignored — the module routes locally; documented in the ABI).
func (t *WASMTransport) SendFrame(ctx context.Context, frame Frame, to RouteHint) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	if len(frame) == 0 || len(frame) > MaxFrameBytes || len(to.RecipientPub) > 64 || len(to.SenderHint) > 64 {
		return &RPCError{Code: ErrInvalid, Detail: "frame out of bounds"}
	}
	fptr, err := t.writeMem(ctx, frame)
	if err != nil {
		return err
	}
	rptr, err := t.writeMem(ctx, to.RecipientPub)
	if err != nil {
		return err
	}
	rc, err := t.callU32(ctx, "ntx_send", fptr, uint64(len(frame)), rptr, uint64(len(to.RecipientPub)))
	if err != nil {
		return err
	}
	switch rc {
	case 0:
		return nil
	case 1:
		return &RPCError{Code: ErrNotReady, Detail: "transport not started"}
	case 3:
		return &RPCError{Code: ErrTransport, Detail: "transport queue full"}
	default:
		return &RPCError{Code: ErrTransport, Detail: fmt.Sprintf("send refused: %d", rc)}
	}
}

// AttachMailbox implements FrameTransport (shard/router URLs are v1-ignored;
// queue-model transports route locally — documented in the ABI header).
func (t *WASMTransport) AttachMailbox(ctx context.Context, mailboxID, readSecret []byte, shardURL, routerURL string) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	if len(mailboxID) != 16 || len(readSecret) != 32 {
		return &RPCError{Code: ErrInvalid, Detail: "bad attach"}
	}
	mptr, err := t.writeMem(ctx, mailboxID)
	if err != nil {
		return err
	}
	sptr, err := t.writeMem(ctx, readSecret)
	if err != nil {
		return err
	}
	rc, err := t.callU32(ctx, "ntx_attach", mptr, sptr, 0, 0, 0, 0)
	_ = shardURL
	_ = routerURL
	if err != nil {
		return err
	}
	if rc != 0 {
		return &RPCError{Code: ErrTransport, Detail: fmt.Sprintf("attach refused: %d", rc)}
	}
	return nil
}

// DetachMailbox implements FrameTransport.
func (t *WASMTransport) DetachMailbox(ctx context.Context, mailboxID []byte) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	if len(mailboxID) != 16 {
		return &RPCError{Code: ErrInvalid, Detail: "bad detach"}
	}
	mptr, err := t.writeMem(ctx, mailboxID)
	if err != nil {
		return err
	}
	rc, err := t.callU32(ctx, "ntx_detach", mptr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return &RPCError{Code: ErrTransport, Detail: fmt.Sprintf("detach refused: %d", rc)}
	}
	return nil
}

// PollFrames implements FrameTransport.
func (t *WASMTransport) PollFrames(ctx context.Context, limit int, mailboxID []byte) ([][]byte, error) {
	if err := t.requireStarted(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	var mptr, has uint64
	if len(mailboxID) == 16 {
		p, err := t.writeMem(ctx, mailboxID)
		if err != nil {
			return nil, err
		}
		mptr, has = p, 1
	}
	blob, err := t.callBlob(ctx, "ntx_poll", uint64(limit), mptr, has)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	pos := 0
	for pos < len(blob) {
		if pos+4 > len(blob) {
			return nil, &RPCError{Code: ErrTransport, Detail: "poll blob truncated"}
		}
		n := int(uint32(blob[pos])<<24 | uint32(blob[pos+1])<<16 | uint32(blob[pos+2])<<8 | uint32(blob[pos+3]))
		pos += 4
		if n <= 0 || n > MaxFrameBytes || pos+n > len(blob) {
			return nil, &RPCError{Code: ErrTransport, Detail: "poll frame out of bounds"}
		}
		out = append(out, append([]byte(nil), blob[pos:pos+n]...))
		pos += n
	}
	return out, nil
}

// Status implements FrameTransport.
func (t *WASMTransport) Status(ctx context.Context) (bool, string, error) {
	rc, err := t.callU32(ctx, "ntx_status")
	if err != nil {
		return false, "", err
	}
	return rc == 1, "wasm", nil
}
