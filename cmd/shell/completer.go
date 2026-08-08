// cmd/shell/completer.go
//
// Tab completion for the interactive sub-shells.
//
// The previous implementation hard-coded a single list of command names and
// only ever completed peer IDs that were already keys in State.Mailbox. That
// had two consequences:
//
//   - Completion drifted from reality. The list omitted commands that exist
//     (`decrypt`, `offer`, `accept`, `finish`, `encrypt`) and offered commands
//     that a given transport doesn't have (`listen` in offline mode), because
//     one flat list was shared by every transport.
//   - Peer IDs mostly didn't complete at all. Mailbox only gains a key once a
//     message is exchanged, so after `connect <id>` — or after `listen`
//     accepted an incoming offer — the peer was invisible to Tab and the full
//     44-character base58 ID had to be retyped or pasted for the next command.
//
// This file replaces that with a completer driven by each transport's own
// registry.CommandSpec list, resolving argument candidates per slot: peer IDs
// and contact aliases for peer slots, local <id>.json profiles for identity
// slots, and nothing for free-text slots.
package shell

import (
	"strings"
	"unicode/utf8"

	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

// shellCompleter implements readline.AutoCompleter for one transport
// sub-shell. It holds a pointer to the live state and re-reads it on every
// keystroke, so a peer learned seconds ago by `connect` or `listen` is
// completable immediately without restarting the shell.
type shellCompleter struct {
	state *RuntimeState
	specs []registry.CommandSpec
}

func newShellCompleter(state *RuntimeState, t registry.GUITransport) *shellCompleter {
	return &shellCompleter{
		state: state,
		specs: registry.CommandsOf(t),
	}
}

// Do implements readline.AutoCompleter.
//
// Contract (see chzyer/readline complete.go): candidates are the *remainder*
// to insert after the already-typed word fragment, and the returned length is
// how many runes of that fragment precede the cursor. Returning byte lengths
// here would corrupt the line for any non-ASCII input, so the fragment is
// measured with utf8.RuneCountInString.
func (c *shellCompleter) Do(line []rune, pos int) ([][]rune, int) {
	if pos > len(line) {
		pos = len(line)
	}
	before := line[:pos]

	// Find the start of the word the cursor sits in. Everything before it is
	// a completed word; everything from it to the cursor is the fragment we
	// are completing. A cursor directly after a space yields an empty
	// fragment, which correctly lists every candidate for that slot.
	start := len(before)
	for start > 0 && !isWordBreak(before[start-1]) {
		start--
	}
	fragment := string(before[start:])
	typed := strings.Fields(string(before[:start]))

	// First word position → complete the command name itself.
	if len(typed) == 0 {
		return suffixes(registry.CommandNames(c.specs), fragment), utf8.RuneCountInString(fragment)
	}

	spec, ok := registry.FindCommand(c.specs, typed[0])
	if !ok {
		// Unknown command — nothing sensible to offer for its arguments.
		return nil, 0
	}

	argIndex := len(typed) - 1 // typed[0] is always the command word.

	slotCandidates := map[registry.ArgKind][]string{
		registry.ArgPeer:     c.state.PeerCandidates(),
		registry.ArgIdentity: c.state.IdentityCandidates(),
	}
	candidates, ok := slotCandidates[spec.ArgKindAt(argIndex)]
	if !ok { // registry.ArgText — free-form, no completion.
		return nil, 0
	}

	return suffixes(candidates, fragment), utf8.RuneCountInString(fragment)
}

// isWordBreak reports whether r separates shell words. Tabs are included
// because readline delivers a literal tab in the buffer when completion is
// disabled for a slot.
func isWordBreak(r rune) bool {
	return r == ' ' || r == '\t'
}

// suffixes filters candidates by fragment and returns the part that still has
// to be inserted, with a trailing space appended so the user can type the next
// argument immediately instead of reaching for the spacebar.
//
// The trailing space is safe with readline's candidate aggregation: when
// several candidates share only a partial prefix, runes.Aggregate emits just
// that shared prefix (which contains no space); the space is only ever
// inserted when a single candidate wins outright.
func suffixes(candidates []string, fragment string) [][]rune {
	out := make([][]rune, 0, len(candidates))
	for _, cand := range candidates {
		if !strings.HasPrefix(cand, fragment) {
			continue
		}
		// Byte slicing is correct here: HasPrefix guarantees fragment is a
		// byte-exact prefix of cand, so len(fragment) lands on a rune
		// boundary.
		out = append(out, []rune(cand[len(fragment):]+" "))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
