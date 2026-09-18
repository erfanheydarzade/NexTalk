package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// RPCTimeout bounds every request/response round trip.
const RPCTimeout = 15 * time.Second

// Process is a spawned transport process speaking framed NanoPack RPC over
// stdio. stdin/stdout are reserved for RPC; the child's stderr is captured
// for diagnostics (never trusted with secrets).
type Process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.Reader
	stderr *bytes.Buffer

	mu    sync.Mutex
	next  uint32
	pend  map[uint32]chan rpcResult
	dying chan struct{}
}

type rpcResult struct {
	env *Envelope
	err error
}

// Spawn starts path with args and performs no handshake yet (call Initialize).
func Spawn(path string, args []string, config []byte) (*Process, error) {
	_ = config
	cmd := exec.Command(path, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: spawn stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("transport: spawn stdout: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("transport: spawn start %q: %w", path, err)
	}
	p := &Process{cmd: cmd, stdin: stdin, stdout: stdout, stderr: &stderr, pend: map[uint32]chan rpcResult{}, dying: make(chan struct{})}
	go p.readLoop()
	return p, nil
}

func (p *Process) readLoop() {
	defer close(p.dying)
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(p.stdout, hdr[:]); err != nil {
			p.failAll(err)
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > MaxRPCBytes {
			p.failAll(fmt.Errorf("transport: rpc: bad frame length %d", n))
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(p.stdout, body); err != nil {
			p.failAll(err)
			return
		}
		env, err := UnmarshalEnvelope(body)
		if err != nil {
			p.failAll(err)
			return
		}
		p.mu.Lock()
		ch, ok := p.pend[env.ReqID]
		if ok {
			delete(p.pend, env.ReqID)
		}
		p.mu.Unlock()
		if ok {
			ch <- rpcResult{env: env}
		}
	}
}

func (p *Process) failAll(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, ch := range p.pend {
		delete(p.pend, id)
		select {
		case ch <- rpcResult{err: err}:
		default:
		}
	}
}

// Call sends one op and awaits the matching response envelope.
func (p *Process) Call(ctx context.Context, op uint8, payload []byte) (*Envelope, error) {
	p.mu.Lock()
	p.next++
	id := p.next
	ch := make(chan rpcResult, 1)
	p.pend[id] = ch
	p.mu.Unlock()

	body, err := MarshalEnvelope(&Envelope{Op: op, ReqID: id, Payload: payload})
	if err != nil {
		return nil, err
	}
	framed := frameMessage(body)

	type wres struct{ err error }
	wch := make(chan wres, 1)
	go func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		_, err := p.stdin.Write(framed)
		wch <- wres{err}
	}()

	timeout := RPCTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d < timeout {
			timeout = d
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case w := <-wch:
		if w.err != nil {
			return nil, fmt.Errorf("transport: rpc write: %w", w.err)
		}
	case <-timer.C:
		return nil, fmt.Errorf("transport: rpc write timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if r.env.Op == OpError {
			rpcErr, err := UnmarshalError(r.env.Payload)
			if err != nil {
				return nil, fmt.Errorf("transport: rpc error (undecodable): %w", err)
			}
			return nil, rpcErr
		}
		if r.env.Op != op {
			return nil, fmt.Errorf("transport: rpc: op mismatch %d != %d", r.env.Op, op)
		}
		return r.env, nil
	case <-timer.C:
		return nil, fmt.Errorf("transport: rpc timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.dying:
		return nil, fmt.Errorf("transport: process exited: %s", p.Stderr())
	}
}

// Stderr returns captured child diagnostics.
func (p *Process) Stderr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stderr == nil {
		return ""
	}
	s := p.stderr.String()
	if len(s) > 4096 {
		s = s[len(s)-4096:]
	}
	return s
}

// Kill terminates the child.
func (p *Process) Kill() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

// Wait reaps the child.
func (p *Process) Wait() error {
	if p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}
