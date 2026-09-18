package transport

import (
	"bytes"
	"testing"

	"github.com/erfanheydarzade/nanopack"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	in := &Envelope{Op: OpSend, ReqID: 42, Payload: []byte("hello")}
	body, err := MarshalEnvelope(in)
	if err != nil {
		t.Fatal(err)
	}
	framed := frameMessage(body)
	if len(framed) != 4+len(body) {
		t.Fatal("framing size mismatch")
	}
	got, err := UnmarshalEnvelope(framed[4:])
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != in.Op || got.ReqID != in.ReqID || !bytes.Equal(got.Payload, in.Payload) {
		t.Fatal("envelope mismatch")
	}
}

func TestEnvelopeRejects(t *testing.T) {
	for _, b := range [][]byte{{}, {0x01, 0x01}, {0x01, 0x01, 0x80}} {
		if _, err := UnmarshalEnvelope(b); err == nil {
			t.Fatalf("must reject %x", b)
		}
	}
	// Unknown op.
	enc := &nanopack.Encoder{}
	enc.AddID(1, []byte{99})
	enc.AddID(2, putU32(1))
	enc.AddID(3, []byte{})
	bad, _ := enc.Bytes()
	if _, err := UnmarshalEnvelope(bad); err == nil {
		t.Fatal("must reject unknown op")
	}
}

func TestPayloadCodecs(t *testing.T) {
	if _, err := MarshalSend(nil, nil, nil, nil, ""); err == nil {
		t.Fatal("empty frame must fail")
	}
	frame := append([]byte{0x03}, bytes.Repeat([]byte{0xAB}, 100)...)
	sb, err := MarshalSend(frame, bytes.Repeat([]byte{1}, 32), nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := UnmarshalSend(sb)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Frame, frame) || len(s.RecipientPub) != 32 {
		t.Fatal("send mismatch")
	}

	ab, _ := MarshalAttach(bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 32), "https://shard", "https://router")
	a, err := UnmarshalAttach(ab)
	if err != nil {
		t.Fatal(err)
	}
	if a.ShardURL != "https://shard" || len(a.ReadSecret) != 32 {
		t.Fatal("attach mismatch")
	}

	frames := [][]byte{frame, frame}
	pr, _ := MarshalPollResult(frames)
	got, err := UnmarshalPollResult(pr)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], frame) {
		t.Fatal("poll result mismatch")
	}

	cb, _ := MarshalCaps([]string{"message"}, "filerelay", "1.0.0")
	caps, err := UnmarshalCaps(cb)
	if err != nil {
		t.Fatal(err)
	}
	if caps.TransportID != "filerelay" || len(caps.Capabilities) != 1 {
		t.Fatal("caps mismatch")
	}

	ib, _ := MarshalInitialize("filerelay", 1, []byte(`{}`))
	init, err := UnmarshalInitialize(ib)
	if err != nil {
		t.Fatal(err)
	}
	if init.APIVersion != 1 || init.TransportID != "filerelay" {
		t.Fatal("init mismatch")
	}

	// Oversize poll result.
	big := make([][]byte, 33)
	if _, err := MarshalPollResult(big); err == nil {
		t.Fatal("33 frames must fail")
	}
}
