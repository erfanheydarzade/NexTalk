package shellcmd

import (
	"fmt"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// Session is the live shell state: who you are, which relay you use, and
// the conveniences (aliases, history, recorded transfers) built up during
// the session. Nothing here holds private keys — commands load the identity
// file on demand and drop it afterwards.
type Session struct {
	// Identity is the active peer ID (from `use identity` / `-i`).
	Identity string
	// Relay is the active runtime transport ID (from `use relay`).
	Relay string
	// TransportsDir overrides the transport manager directory.
	TransportsDir string
	// Aliases maps a word to its expansion, e.g. xsend -> "xfer send".
	Aliases map[string]string
	// History is the in-session command log (never written to disk:
	// history lines can contain pasted blobs and bearer secrets).
	History []string
	// JSON makes human-intended output machine-readable instead.
	JSON bool
	// ShowSecrets disables secret redaction. Off unless explicitly enabled.
	ShowSecrets bool
	// Transfers records transfers created in this session for `context`
	// and `xfer list`. Each entry: transferID hex, file name, bytes.
	Transfers []TransferRef
	// Interactive is true in the live terminal loop, false for piped
	// scripting. Non-interactive mode auto-confirms (with a stderr note)
	// and refuses hidden prompts (pass secrets as flags instead).
	Interactive bool
	// Peers remembers peer IDs learned this session (sends, receives,
	// handshakes) for Tab completion. registry.State keeps its own
	// richer set for legacy sub-shells; this one serves the unified shell.
	Peers []string
	// PeerMailboxes maps lowercase hex ed25519 pubkey → explicit recipient
	// address for address-shared relays (e.g. filerelay scoped mailboxes,
	// unguessable from the peer key). Consulted by auto-replies and sends
	// before falling back to pubkey routing. Populated by `peer address`.
	PeerMailboxes map[string]PeerAddr
}

// PeerAddr is one peer's explicit relay address.
type PeerAddr struct {
	PeerID    string // peer ID as learned (display only)
	MailboxID string // 32 lowercase hex (16B)
	ShardURL  string
}

// TransferRef is one session-known file transfer.
type TransferRef struct {
	ID   string
	File string
	Size int
	// TicketB64 holds the base64 NanoPack ticket when the transfer was
	// created for sharing (empty for direct-delivery transfers).
	TicketB64 string
}

// NewSession returns an empty session with default aliases.
func NewSession() *Session {
	return &Session{
		Aliases: map[string]string{
			"xsend": "xfer send",
			"xget":  "xfer recv",
		},
		PeerMailboxes: map[string]PeerAddr{},
	}
}

// ExpandAlias replaces a leading alias word with its expansion.
// Expansion applies once (no chains), so aliases can never loop.
func (s *Session) ExpandAlias(words []string) []string {
	if len(words) == 0 || s == nil {
		return words
	}
	exp, ok := s.Aliases[strings.ToLower(words[0])]
	if !ok || exp == "" {
		return words
	}
	return append(strings.Fields(exp), words[1:]...)
}

// RecordTransfer remembers a transfer for `context` / `xfer list`.
func (s *Session) RecordTransfer(ref TransferRef) {
	if s == nil {
		return
	}
	for i, t := range s.Transfers {
		if t.ID == ref.ID {
			s.Transfers[i] = ref
			return
		}
	}
	s.Transfers = append(s.Transfers, ref)
}

// RememberPeer records a peer ID for completion (deduped).
func (s *Session) RememberPeer(id string) {
	if s == nil || id == "" {
		return
	}
	for _, p := range s.Peers {
		if p == id {
			return
		}
	}
	s.Peers = append(s.Peers, id)
}

// Prompt renders the environment/context display, e.g.
// ╭─[nextalk:alice@relay1]. Missing pieces render as "-".
// Kept plain on purpose: readline redraws its prompt on every keystroke and
// miscounts ANSI escapes, so the readline-owned prompt must stay escape-free.
// Print PromptColored with fmt for the colorful one-line-above variant.
func (s *Session) Prompt() string {
	id, relay := "-", "-"
	if s != nil {
		if s.Identity != "" {
			id = shortID(s.Identity)
		}
		if s.Relay != "" {
			relay = s.Relay
		}
	}
	return fmt.Sprintf("╭─[nextalk:%s@%s]", id, relay)
}

// PromptColored renders the same environment line with theme colors:
// identity in green, relay in magenta, frame in cyan. Safe to print with
// fmt once per input line (never as the readline-owned prompt itself).
func (s *Session) PromptColored() string {
	id, relay := "-", "-"
	if s != nil {
		if s.Identity != "" {
			id = shortID(s.Identity)
		}
		if s.Relay != "" {
			relay = s.Relay
		}
	}
	return ui.PromptContext(id, relay)
}

// StatusLine renders a friendly one-line summary: ● identity  ● relay,
// with missing pieces dimmed and hinted. Used by `context` and the welcome
// screen.
func (s *Session) StatusLine() string {
	id, relay := "-", "-"
	if s != nil {
		if s.Identity != "" {
			id = s.Identity
		}
		if s.Relay != "" {
			relay = s.Relay
		}
	}
	idDot := ui.Success.Sprint("●")
	relayDot := ui.Relay.Sprint("●")
	if id == "-" {
		idDot = ui.Dim.Sprint("○")
		id = ui.Dim.Sprint("- (use `use identity <id>`)")
	} else {
		id = ui.Identity.Sprint(shortID(id))
	}
	if relay == "-" {
		relayDot = ui.Dim.Sprint("○")
		relay = ui.Dim.Sprint("- (use `use relay <id>`)")
	} else {
		relay = ui.Relay.Sprint(relay)
	}
	return fmt.Sprintf("%s identity %s   %s relay %s", idDot, id, relayDot, relay)
}

func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-4:]
}
