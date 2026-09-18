package shellcmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/ui"
	"github.com/fatih/color"
)

// paintPrefix colors a leading status marker (long or short form) and
// code-highlights the rest of the line.
func paintPrefix(body, long, short string, c *color.Color) string {
	if strings.HasPrefix(body, long) {
		return c.Sprint(long) + ui.CodeSpan(body[len(long):])
	}
	return c.Sprint(short) + ui.CodeSpan(body[len(short):])
}

// Redacted is the placeholder printed for secret values unless secrets are
// explicitly enabled. The values it guards: read_secret bearer, download
// ticket secrets, private keys, scoped relay credentials.
const Redacted = "********"

// Secret renders v for human output: the value itself when show is true,
// Redacted otherwise.
func Secret(v string, show bool) string {
	if show {
		return v
	}
	if v == "" {
		return ""
	}
	return Redacted
}

// WriteJSON writes v as one JSON line to w — the machine-readable form.
// Every command that has something scriptable to say uses this in --json
// mode, so pipes always see exactly one document per invocation.
func WriteJSON(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(raw))
	return err
}

// Human writes a human-UI line to stderr writers. Interactive callers pass
// os.Stderr; tests pass a buffer. Keeping UI off stdout is what keeps
// stdout pipe-safe for scripts.
//
// Human is color-aware: status markers (✓, ✗, [!], [i], [✉], [+]) get their
// theme color and `backticked` spans render as highlighted code. Colors are
// no-ops when output is piped (fatih/color disables itself), so scripts and
// tests still see plain text.
func Human(w io.Writer, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	_, _ = io.WriteString(w, colorizeHuman(msg))
}

// colorizeHuman applies theme colors to one already-formatted line.
func colorizeHuman(msg string) string {
	trimmed := strings.TrimRight(msg, "\n")
	indent := msg[:len(msg)-len(strings.TrimLeft(msg, " \t"))]
	body := strings.TrimLeft(trimmed, " \t")

	colored := body
	switch {
	case strings.HasPrefix(body, "[✓]") || strings.HasPrefix(body, "✓"):
		colored = paintPrefix(body, "[✓]", "✓", ui.Success)
	case strings.HasPrefix(body, "[✗]") || strings.HasPrefix(body, "✗"):
		colored = paintPrefix(body, "[✗]", "✗", ui.Fail)
	case strings.HasPrefix(body, "[!]"):
		colored = ui.Warning.Sprint("[!]") + ui.CodeSpan(body[3:])
	case strings.HasPrefix(body, "[i]"):
		colored = ui.Info.Sprint("[i]") + ui.CodeSpan(body[3:])
	case strings.HasPrefix(body, "[✉]"):
		colored = ui.Mail.Sprint("[✉]") + ui.CodeSpan(body[len("[✉]"):])
	case strings.HasPrefix(body, "[+]"):
		colored = ui.Success.Sprint("[+]") + ui.CodeSpan(body[3:])
	case strings.HasPrefix(body, "[?]"):
		colored = ui.Warning.Sprint("[?]") + ui.CodeSpan(body[3:])
	case strings.HasPrefix(body, "ID:") || strings.HasPrefix(body, "Ticket:") ||
		strings.HasPrefix(body, "Identity:") || strings.HasPrefix(body, "Relay:") ||
		strings.HasPrefix(body, "Active transfers:"):
		colored = ui.Title.Sprint(body)
	default:
		colored = ui.CodeSpan(body)
	}
	// Preserve trailing newline(s).
	suffix := msg[len(trimmed):]
	return indent + colored + suffix
}
