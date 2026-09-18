package transport

import (
	"context"
	"fmt"
	"sync"
)

// ProcessTransport adapts a spawned transport process to FrameTransport.
type ProcessTransport struct {
	manifest *Manifest
	proc     *Process
	config   []byte

	mu      sync.Mutex
	started bool
	caps    []string
	version string
}

// NewProcessTransport spawns the entry binary and runs initialize + capabilities.
func NewProcessTransport(ctx context.Context, binPath string, m *Manifest, config []byte) (*ProcessTransport, error) {
	proc, err := Spawn(binPath, []string{"--ntx-serve"}, config)
	if err != nil {
		return nil, err
	}
	t := &ProcessTransport{manifest: m, proc: proc, config: config}
	initPayload, err := MarshalInitialize(m.ID, TransportAPIVersion, config)
	if err != nil {
		proc.Kill()
		return nil, err
	}
	env, err := proc.Call(ctx, OpInitialize, initPayload)
	if err != nil {
		proc.Kill()
		return nil, fmt.Errorf("transport %q initialize: %w (stderr: %s)", m.ID, err, proc.Stderr())
	}
	res, err := UnmarshalInitResult(env.Payload)
	if err != nil {
		proc.Kill()
		return nil, fmt.Errorf("transport %q initialize: %w", m.ID, err)
	}
	if !res.OK || res.ActualAPI != TransportAPIVersion {
		proc.Kill()
		return nil, fmt.Errorf("transport %q initialize refused: %s (api %d)", m.ID, res.Detail, res.ActualAPI)
	}
	caps, err := t.queryCaps(ctx)
	if err != nil {
		proc.Kill()
		return nil, err
	}
	if caps.TransportID != m.ID {
		proc.Kill()
		return nil, fmt.Errorf("transport %q id mismatch from process %q", m.ID, caps.TransportID)
	}
	t.caps = caps.Capabilities
	t.version = caps.Version
	return t, nil
}

func (t *ProcessTransport) queryCaps(ctx context.Context) (*Caps, error) {
	// Capabilities request has an empty payload; the op byte selects the schema.
	env, err := t.proc.Call(ctx, OpCapabilities, []byte{0x00})
	if err != nil {
		return nil, err
	}
	return UnmarshalCaps(env.Payload)
}

// ID implements FrameTransport.
func (t *ProcessTransport) ID() string { return t.manifest.ID }

// Capabilities implements FrameTransport.
func (t *ProcessTransport) Capabilities() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.caps...)
}

// Version is the transport's own version string.
func (t *ProcessTransport) Version() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.version
}

// Manifest returns the pinned manifest.
func (t *ProcessTransport) Manifest() *Manifest { return t.manifest }

// Start implements FrameTransport.
func (t *ProcessTransport) Start(ctx context.Context) error {
	payload, _ := MarshalStartStop(ActionStart)
	env, err := t.proc.Call(ctx, OpStartStop, payload)
	if err != nil {
		return err
	}
	ack, err := UnmarshalAck(env.Payload)
	if err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("transport %q start: %s", t.manifest.ID, ack.Detail)
	}
	t.mu.Lock()
	t.started = true
	t.mu.Unlock()
	return nil
}

// Stop implements FrameTransport.
func (t *ProcessTransport) Stop(ctx context.Context) error {
	payload, _ := MarshalStartStop(ActionStop)
	env, err := t.proc.Call(ctx, OpStartStop, payload)
	if err != nil {
		return err
	}
	ack, err := UnmarshalAck(env.Payload)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.started = false
	t.mu.Unlock()
	if !ack.OK {
		return fmt.Errorf("transport %q stop: %s", t.manifest.ID, ack.Detail)
	}
	return nil
}

func (t *ProcessTransport) requireStarted() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started {
		return fmt.Errorf("transport %q not started", t.manifest.ID)
	}
	return nil
}

// SendFrame implements FrameTransport.
func (t *ProcessTransport) SendFrame(ctx context.Context, frame Frame, to RouteHint) error {
	if err := t.requireStarted(); err != nil {
		return &RPCError{Code: ErrNotReady, Detail: err.Error()}
	}
	payload, err := MarshalSend(frame, to.RecipientPub, to.SenderHint, to.MailboxID, to.ShardURL)
	if err != nil {
		return err
	}
	env, err := t.proc.Call(ctx, OpSend, payload)
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

// AttachMailbox implements FrameTransport.
func (t *ProcessTransport) AttachMailbox(ctx context.Context, mailboxID, readSecret []byte, shardURL, routerURL string) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	payload, err := MarshalAttach(mailboxID, readSecret, shardURL, routerURL)
	if err != nil {
		return err
	}
	env, err := t.proc.Call(ctx, OpAttach, payload)
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

// DetachMailbox implements FrameTransport.
func (t *ProcessTransport) DetachMailbox(ctx context.Context, mailboxID []byte) error {
	if err := t.requireStarted(); err != nil {
		return err
	}
	payload, err := MarshalDetach(mailboxID)
	if err != nil {
		return err
	}
	env, err := t.proc.Call(ctx, OpDetach, payload)
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

// PollFrames implements FrameTransport.
func (t *ProcessTransport) PollFrames(ctx context.Context, limit int, mailboxID []byte) ([][]byte, error) {
	if err := t.requireStarted(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	payload, err := MarshalPoll(uint8(limit), mailboxID)
	if err != nil {
		return nil, err
	}
	env, err := t.proc.Call(ctx, OpPoll, payload)
	if err != nil {
		return nil, err
	}
	return UnmarshalPollResult(env.Payload)
}

// Status implements FrameTransport.
func (t *ProcessTransport) Status(ctx context.Context) (bool, string, error) {
	env, err := t.proc.Call(ctx, OpStatus, []byte{0x00})
	if err != nil {
		return false, "", err
	}
	st, err := UnmarshalStatus(env.Payload)
	if err != nil {
		return false, "", err
	}
	return st.Running, st.Detail, nil
}

// Kill force-terminates the child (quarantine path).
func (t *ProcessTransport) Kill() error { return t.proc.Kill() }
