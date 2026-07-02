package crypto

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

// GenerateX25519KeyPair generates a new X25519 (Curve25519) key pair.
//
// The private key is randomly sampled from a cryptographically secure RNG,
// and the public key is derived via scalar multiplication on the base point.
//
// This is used as the foundational identity material for Diffie-Hellman
// key exchange in the system.
func GenerateX25519KeyPair() ([]byte, []byte) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv[:], pub[:]
}