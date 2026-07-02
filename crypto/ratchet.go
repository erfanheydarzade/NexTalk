package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// RatchetStep derives the next chain key and message key from the current chain key (ck)
// using HKDF-SHA256.
//
// This provides forward secrecy: each step produces a new state (nextCk)
// and an independent message key (mk), so compromise of one state does not
// expose other messages.
//
// "ratchet-step" binds the derivation to this protocol context.
func RatchetStep(ck []byte) (nextCk, mk []byte) {
	info := []byte("ratchet-step")
	material := make([]byte, 64)

	hkdfReader := hkdf.New(sha256.New, ck, nil, info)
	io.ReadFull(hkdfReader, material)

	nextCk = material[:32]
	mk = material[32:]
	return
}

// IntToBytes converts an integer into a fixed-length big-endian byte slice.
// Used for deterministic encoding in protocol-level operations.
func IntToBytes(n int, length int) []byte {
	b := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	return b
}
