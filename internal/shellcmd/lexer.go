package shellcmd

import (
	"fmt"
	"strings"
)

// SplitLine tokenizes one interactive shell command.
// Quotes are syntax, not part of the resulting argument. Backslashes are
// preserved literally because Windows paths use them as separators.
func SplitLine(line string) ([]string, error) {
	var out []string
	var b strings.Builder
	var quote rune
	have := false

	flush := func() {
		if have {
			out = append(out, b.String())
			b.Reset()
			have = false
		}
	}

	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			have = true
		case r == '\'' || r == '"':
			quote = r
			have = true
		case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			flush()
		default:
			b.WriteRune(r)
			have = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	flush()
	return out, nil
}
