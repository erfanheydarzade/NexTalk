// This module implements a lightweight Proquint encoding/decoding system
// for representing binary data in a human-readable and pronounceable format.
//
// Proquint is used to convert raw byte sequences into structured words,
// and back again, making it easier to handle binary identifiers in logs,
// debugging sessions, and development workflows.
//
// Although this component is not currently part of the core cryptographic
// pipeline, it is included as a utility module because it may become useful
// in future versions of the system for:
//
//   - Human-readable representation of cryptographic keys or identifiers
//   - Debugging and inspection of binary session data
//   - Logging encoded values in a more readable form
//   - Potential use in identity or session visualization layers
//
// The module is intentionally kept independent from the main crypto flow,
// allowing it to be safely used as an optional encoding layer without
// affecting security-critical components.

package crypto

import (
	"errors"
	"strings"
)

var (
	consonants = []rune("bdfghjklmnprstvz")
	vowels     = []rune("aiou")
)

func ToProquint(data []byte) string {
	var result []string
	for i := 0; i < len(data); i += 2 {
		val := uint16(data[i]) << 8
		if i+1 < len(data) {
			val |= uint16(data[i+1])
		}

		c1 := (val >> 12) & 0x0F
		v1 := (val >> 10) & 0x03
		c2 := (val >> 6) & 0x0F
		v2 := (val >> 4) & 0x03
		c3 := val & 0x0F

		word := string([]rune{
			consonants[c1], vowels[v1], consonants[c2], vowels[v2], consonants[c3],
		})
		result = append(result, word)
	}
	return strings.Join(result, "-")
}

func FromProquint(input string) ([]byte, error) {
	words := strings.Split(input, "-")
	var result []byte

	consonantMap := make(map[rune]uint16)
	for i, r := range consonants {
		consonantMap[r] = uint16(i)
	}
	vowelMap := make(map[rune]uint16)
	for i, r := range vowels {
		vowelMap[r] = uint16(i)
	}

	for _, word := range words {
		if len(word) != 5 {
			return nil, errors.New("invalid word length")
		}

		r := []rune(word)
		c1, ok1 := consonantMap[r[0]]
		v1, ok2 := vowelMap[r[1]]
		c2, ok3 := consonantMap[r[2]]
		v2, ok4 := vowelMap[r[3]]
		c3, ok5 := consonantMap[r[4]]

		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			return nil, errors.New("invalid character in proquint")
		}

		val := (c1 << 12) | (v1 << 10) | (c2 << 6) | (v2 << 4) | c3
		result = append(result, byte(val>>8), byte(val&0xFF))
	}
	return result, nil
}
