package transport

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// fakeServe speaks the RPC as a minimal "fake" transport. It runs inside the
// test binary as a helper process (env NTX_FAKE_TRANSPORT=1).
func fakeServe() {
	var stored [][]byte
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(os.Stdin, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > MaxRPCBytes {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(os.Stdin, body); err != nil {
			return
		}
		env, err := UnmarshalEnvelope(body)
		if err != nil {
			return
		}
		var respOp = env.Op
		var payload []byte
		switch env.Op {
		case OpInitialize:
			init, err := UnmarshalInitialize(env.Payload)
			if err != nil || init.TransportID != "fake" || init.APIVersion != TransportAPIVersion {
				payload, _ = MarshalInitResult(false, "bad init", TransportAPIVersion)
				break
			}
			payload, _ = MarshalInitResult(true, "", TransportAPIVersion)
		case OpCapabilities:
			payload, _ = MarshalCaps([]string{"message"}, "fake", "0.0.1")
		case OpStartStop:
			payload, _ = MarshalAck(true, "")
		case OpSend:
			s, err := UnmarshalSend(env.Payload)
			if err != nil {
				payload, _ = MarshalAck(false, err.Error())
				break
			}
			stored = append(stored, s.Frame)
			payload, _ = MarshalAck(true, "")
		case OpAttach, OpDetach:
			payload, _ = MarshalAck(true, "")
		case OpPoll:
			p, err := UnmarshalPoll(env.Payload)
			if err != nil {
				payload, _ = MarshalError(ErrInvalid, err.Error())
				respOp = env.Op
				break
			}
			limit := int(p.Limit)
			if limit > len(stored) {
				limit = len(stored)
			}
			out := append([][]byte(nil), stored[:limit]...)
			stored = stored[limit:]
			payload, _ = MarshalPollResult(out)
		case OpStatus:
			payload, _ = MarshalStatus(true, "fake ok")
		default:
			payload, _ = MarshalError(ErrUnsupported, "unknown op")
		}
		_ = respOp
		rbody, _ := MarshalEnvelope(&Envelope{Op: env.Op, ReqID: env.ReqID, Payload: payload})
		out := frameMessage(rbody)
		if _, err := os.Stdout.Write(out); err != nil {
			return
		}
	}
}

func fakeProcess(t *testing.T) *Process {
	t.Helper()
	if os.Getenv("NTX_FAKE_TRANSPORT") == "1" {
		t.Skip("already the helper")
	}
	cmd := exec.Command(os.Args[0], "--ntx-serve")
	cmd.Env = append(os.Environ(), "NTX_FAKE_TRANSPORT=1")
	// Bypass Spawn to inject env: replicate its stdio wiring.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	p := &Process{cmd: cmd, stdin: stdin, stdout: stdout, pend: map[uint32]chan rpcResult{}, dying: make(chan struct{})}
	go p.readLoop()
	return p
}

func TestMain(m *testing.M) {
	if os.Getenv("NTX_FAKE_TRANSPORT") == "1" {
		fakeServe()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestProcessRoundTrip(t *testing.T) {
	p := fakeProcess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	initPayload, _ := MarshalInitialize("fake", TransportAPIVersion, []byte(`{}`))
	env, err := p.Call(ctx, OpInitialize, initPayload)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := UnmarshalInitResult(env.Payload)
	if !res.OK {
		t.Fatal("init refused")
	}

	frame := append([]byte{0x03}, []byte("opaque")...)
	sendPayload, _ := MarshalSend(frame, make([]byte, 32), nil, nil, "")
	if _, err := p.Call(ctx, OpSend, sendPayload); err != nil {
		t.Fatal(err)
	}
	pollPayload, _ := MarshalPoll(10, nil)
	env, err = p.Call(ctx, OpPoll, pollPayload)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := UnmarshalPollResult(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0][0] != 0x03 {
		t.Fatalf("poll mismatch: %v", frames)
	}
}

func TestProcessTransportFace(t *testing.T) {
	// Full FrameTransport over the helper process.
	if os.Getenv("NTX_FAKE_TRANSPORT") == "1" {
		t.Skip("helper")
	}
	p := fakeProcess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mf, err := ParseManifest([]byte(`{"id":"fake","name":"Fake","version":"0.0.1","api_version":"1","entry":"fake","capabilities":["message"],"permissions":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	pt := &ProcessTransport{manifest: mf, proc: p}
	// Drive the same handshake NewProcessTransport performs.
	initPayload, _ := MarshalInitialize("fake", TransportAPIVersion, nil)
	env, err := p.Call(ctx, OpInitialize, initPayload)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := UnmarshalInitResult(env.Payload); !res.OK {
		t.Fatal("init refused")
	}
	if err := pt.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pt.SendFrame(ctx, []byte{0x03, 0x01}, RouteHint{RecipientPub: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	got, err := pt.PollFrames(ctx, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 frame, got %d", len(got))
	}
	running, _, err := pt.Status(ctx)
	if err != nil || !running {
		t.Fatal("status must be running")
	}
	if err := pt.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
