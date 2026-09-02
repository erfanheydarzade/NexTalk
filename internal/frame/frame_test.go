package frame

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	payload := []byte("nanopack-body-here")
	f := Wrap(TypeMultiMsg, payload)

	t2, p2, err := Unwrap(f)
	if err != nil {
		t.Fatal(err)
	}
	if t2 != TypeMultiMsg || string(p2) != string(payload) {
		t.Fatalf("got type=%d payload=%q", t2, p2)
	}
}

func TestUnwrapRejectsUnknownAndShort(t *testing.T) {
	if _, _, err := Unwrap([]byte{0x7F}); err == nil {
		t.Error("expected error for unknown type byte")
	}
	if _, _, err := Unwrap([]byte{0x04}); err == nil {
		t.Error("expected error for frame without payload")
	}
}

func TestContainerCurrentShape(t *testing.T) {
	container, err := EncodeContainer(TypeMessage, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeContainer(container)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != TypeMessage || string(dec.Payload) != "hi" {
		t.Fatalf("decoded %+v", dec)
	}
}

// TestContainerLegacyShape pins backward compatibility with the historical
// offline envelope whose Data was base64 of the BARE payload (no frame byte).
func TestContainerLegacyShape(t *testing.T) {
	legacy, _ := json.Marshal(Container{
		Type: "offer",
		Data: base64.StdEncoding.EncodeToString([]byte(`{"legacy":true}`)),
	})
	dec, err := DecodeContainer(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != TypeOffer || string(dec.Payload) != `{"legacy":true}` {
		t.Fatalf("decoded %+v", dec)
	}
}

// TestContainerAmbiguityGuard ensures a bare payload that happens to start
// with a non-frame byte is NOT misread as a full frame, and that a Type
// field disagreeing with the frame byte is rejected.
func TestContainerAmbiguityGuard(t *testing.T) {
	// Bare payload starting with 0x0A (10 fields — an offer's field count):
	// not a registered type, so legacy interpretation via Type must win.
	blob := append([]byte{0x0A}, []byte("payload")...)
	cur, _ := json.Marshal(Container{Type: "answer", Data: base64.StdEncoding.EncodeToString(blob)})
	dec, err := DecodeContainer(cur)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != TypeAnswer {
		t.Fatalf("legacy shape misclassified: %+v", dec)
	}

	// Frame byte says 0x03 but Type says offer → refuse to guess.
	conflicting, _ := json.Marshal(Container{Type: "offer", Data: base64.StdEncoding.EncodeToString(Wrap(TypeMessage, []byte("x")))})
	if _, err := DecodeContainer(conflicting); err == nil {
		t.Fatal("conflicting container accepted")
	}

	// Unknown Type name.
	unknown, _ := json.Marshal(Container{Type: "carrier-pigeon", Data: base64.StdEncoding.EncodeToString(blob)})
	if _, err := DecodeContainer(unknown); err == nil {
		t.Fatal("unknown type name accepted")
	}
}

func TestDecodeRawFrame(t *testing.T) {
	dec, err := DecodeContainer(Wrap(TypeMultiMsg, []byte("raw")))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != TypeMultiMsg || string(dec.Payload) != "raw" {
		t.Fatalf("decoded %+v", dec)
	}
}
