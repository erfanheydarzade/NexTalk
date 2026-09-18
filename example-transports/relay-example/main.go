// Command relay-example is a complete third-party NexTalk transport and the
// copy-paste template for building your own.
//
// Model: filesystem queue. A mailbox is hex(ed25519 pubkey); send appends an
// opaque frame file, poll drains it. No network, no keys, no crypto — frames
// are opaque bytes the core encrypted. See README.md for the template walkthrough.
//
// Usage: relay-example --ntx-serve   (stdio RPC; stderr = logs)
// Data:  <transport-dir>/relay-example/data (override with NTX_EXAMPLE_DIR)
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type queue struct {
	mu      sync.Mutex
	base    string
	running bool
	secrets map[string][32]byte // mailboxHex -> sha256(readSecret)
}

func dataDir() string {
	if v := os.Getenv("NTX_EXAMPLE_DIR"); v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "relay-example-data")
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

func (q *queue) mboxPath(mailboxHex string) string {
	return filepath.Join(q.base, mailboxHex)
}

func (q *queue) attach(mailboxHex string, secret []byte) error {
	if len(mailboxHex) != 32 || !isHex(mailboxHex) {
		return fmt.Errorf("mailbox must be 64 hex chars")
	}
	if len(secret) != 32 {
		return fmt.Errorf("read_secret must be 32 bytes")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.secrets[mailboxHex] = sha256.Sum256(secret)
	if err := os.MkdirAll(q.mboxPath(mailboxHex), 0o755); err != nil {
		return err
	}
	return nil
}

func (q *queue) check(mailboxHex string, secret []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	want, ok := q.secrets[mailboxHex]
	if !ok {
		return false
	}
	h := sha256.Sum256(secret)
	return subtle.ConstantTimeCompare(h[:], want[:]) == 1
}

// send appends one frame to mailbox hex(recipientPub). Anyone holding the
// 32B recipient pub can write; only the read-secret holder can read.
func (q *queue) send(recipientPub, frame []byte) error {
	if len(recipientPub) != 32 {
		return fmt.Errorf("recipient_pub must be 32 bytes")
	}
	if len(frame) == 0 || len(frame) > maxFrameBytes {
		return fmt.Errorf("frame out of bounds")
	}
	sum := sha256.Sum256(recipientPub); mbox := hex.EncodeToString(sum[:16])
	if err := os.MkdirAll(q.mboxPath(mbox), 0o755); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(q.mboxPath(mbox), fmt.Sprintf(".tmp-%x", rnd))
	dst := filepath.Join(q.mboxPath(mbox), fmt.Sprintf("%x.frame", rnd))
	if err := os.WriteFile(tmp, frame, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// poll drains up to limit frames from an attached mailbox.
func (q *queue) poll(mailboxHex string, secret []byte, limit int) ([][]byte, error) {
	if !q.check(mailboxHex, secret) {
		return nil, fmt.Errorf("not attached or bad secret")
	}
	entries, err := os.ReadDir(q.mboxPath(mailboxHex))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".frame" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	var out [][]byte
	for _, n := range names {
		if len(out) >= limit {
			break
		}
		raw, err := os.ReadFile(filepath.Join(q.mboxPath(mailboxHex), n))
		if err != nil {
			continue
		}
		if len(raw) == 0 || len(raw) > maxFrameBytes {
			continue
		}
		out = append(out, raw)
		_ = os.Remove(filepath.Join(q.mboxPath(mailboxHex), n)) // burn-after-read
	}
	return out, nil
}

func (q *queue) pollAny(secretByMbox map[string][]byte, only string, limit int) ([][]byte, error) {
	// Poll one mailbox (or all attached when only == "").
	if only != "" {
		sec, ok := secretByMbox[only]
		if !ok {
			return nil, fmt.Errorf("mailbox not attached")
		}
		return q.poll(only, sec, limit)
	}
	var out [][]byte
	// Deterministic order for tests.
	var ids []string
	for id := range secretByMbox {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		got, err := q.poll(id, secretByMbox[id], limit-len(out))
		if err != nil {
			continue
		}
		out = append(out, got...)
	}
	return out, nil
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func main() {
	// Helper: relay-example mailbox --pub <64-hex ed pub> prints the
	// mailbox id to attach (hex(sha256(pub)[:16])).
	if len(os.Args) > 1 && os.Args[1] == "mailbox" {
		fs := flag.NewFlagSet("mailbox", flag.ExitOnError)
		pubHex := fs.String("pub", "", "64-hex Ed25519 pubkey")
		_ = fs.Parse(os.Args[2:])
		raw, err := hex.DecodeString(*pubHex)
		if err != nil || len(raw) != 32 {
			fmt.Fprintln(os.Stderr, "mailbox: --pub must be 64 hex chars")
			os.Exit(2)
		}
		sum := sha256.Sum256(raw)
		fmt.Println(hex.EncodeToString(sum[:16]))
		return
	}
	// Helper: relay-example wrap --type 3 -f payload.bin > frame.bin
	// prepends the layer-1 type byte (offer=1 answer=2 message=3 multimsg=4).
	if len(os.Args) > 1 && os.Args[1] == "wrap" {
		fs := flag.NewFlagSet("wrap", flag.ExitOnError)
		typ := fs.Int("type", 3, "frame type byte (1..4)")
		file := fs.String("f", "", "payload file")
		_ = fs.Parse(os.Args[2:])
		if *typ < 1 || *typ > 4 || *file == "" {
			fmt.Fprintln(os.Stderr, "wrap: --type 1..4 and -f file required")
			os.Exit(2)
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wrap:", err)
			os.Exit(1)
		}
		out := make([]byte, 1+len(raw))
		out[0] = byte(*typ)
		copy(out[1:], raw)
		if _, err := os.Stdout.Write(out); err != nil {
			os.Exit(1)
		}
		return
	}
	serve := flag.Bool("ntx-serve", false, "serve NexTalk transport RPC on stdio")
	flag.Parse()
	if !*serve {
		fmt.Fprintln(os.Stderr, "usage: relay-example --ntx-serve")
		os.Exit(2)
	}
	q := &queue{base: dataDir(), secrets: map[string][32]byte{}}
	if err := os.MkdirAll(q.base, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "data dir:", err)
		os.Exit(1)
	}
	serveLoop(q)
}

func serveLoop(q *queue) {
	// attached secrets mirrored for poll-any (same process, no extra store).
	attached := map[string][]byte{}
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(os.Stdin, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > maxRPCBytes {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(os.Stdin, body); err != nil {
			return
		}
		env, err := unmarshalEnvelope(body)
		if err != nil {
			return
		}
		respOp, payload := dispatchOp(q, attached, env.op, env.payload)
		rbody, err := marshalEnvelope(respOp, env.reqID, payload)
		if err != nil {
			return
		}
		if _, err := os.Stdout.Write(frameMessage(rbody)); err != nil {
			return
		}
	}
}

func dispatchOp(q *queue, attached map[string][]byte, op uint8, payload []byte) (uint8, []byte) {
	// Failures use op 0 (SchemaError) so the core can surface typed errors;
	// successes echo the request op with the typed response.
	switch op {
	case opInitialize:
		init, err := unmarshalInitialize(payload)
		if err != nil || init.transportID != exampleID || init.apiVersion != transportAPIVer {
			return opInitialize, marshalInitResult(false, "id/api mismatch", transportAPIVer)
		}
		return opInitialize, marshalInitResult(true, "", transportAPIVer)
	case opCapabilities:
		return opCapabilities, marshalCaps()
	case opStartStop:
		action, err := unmarshalStartStop(payload)
		if err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		q.mu.Lock()
		q.running = action == actionStart
		q.mu.Unlock()
		return opStartStop, marshalAck(true, "")
	case opSend:
		q.mu.Lock()
		running := q.running
		q.mu.Unlock()
		if !running {
			return opError, marshalErrorPayload(errNotReady, "not started")
		}
		s, err := unmarshalSend(payload)
		if err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		if err := q.send(s.recipientPub, s.frame); err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		return opSend, marshalAck(true, "")
	case opAttach:
		a, err := unmarshalAttach(payload)
		if err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		if err := q.attach(hex.EncodeToString(a.mailboxID), a.readSecret); err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		attached[hex.EncodeToString(a.mailboxID)] = append([]byte(nil), a.readSecret...)
		return opAttach, marshalAck(true, "")
	case opDetach:
		id, err := unmarshalDetach(payload)
		if err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		q.mu.Lock()
		delete(q.secrets, hex.EncodeToString(id))
		q.mu.Unlock()
		delete(attached, hex.EncodeToString(id))
		return opDetach, marshalAck(true, "")
	case opPoll:
		p, err := unmarshalPoll(payload)
		if err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		var only string
		if len(p.mailboxID) == 16 {
			only = hex.EncodeToString(p.mailboxID)
		}
		frames, err := q.pollAny(attached, only, int(p.limit))
		if err != nil {
			return opError, marshalErrorPayload(errTransport, err.Error())
		}
		return opPoll, marshalPollResult(frames)
	case opStatus:
		q.mu.Lock()
		running := q.running
		q.mu.Unlock()
		if running {
			return opStatus, marshalStatus(true, "queue running")
		}
		return opStatus, marshalStatus(false, "stopped")
	default:
		return opError, marshalErrorPayload(errUnsupported, "unknown op")
	}
}
