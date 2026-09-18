package shell

import (
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/erfanheydarzade/NexTalk/internal/contacts"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
)

// unifiedCompleter completes the unified command tree: group and leaf names,
// --flag names, and value slots (peers, identities, threads, transports).
// It re-reads live state on every keystroke, exactly like the legacy
// per-transport completer.
type unifiedCompleter struct {
	session *shellcmd.Session
	reg     *shellcmd.Registry
}

func newUnifiedCompleter(session *shellcmd.Session, reg *shellcmd.Registry) *unifiedCompleter {
	return &unifiedCompleter{session: session, reg: reg}
}

// Do implements readline.AutoCompleter. See cmd/shell/completer.go for the
// remainder/offset contract (suffixes + rune counts, never byte counts).
func (c *unifiedCompleter) Do(line []rune, pos int) ([][]rune, int) {
	if pos > len(line) {
		pos = len(line)
	}
	before := line[:pos]

	start := len(before)
	for start > 0 && !isWordBreak(before[start-1]) {
		start--
	}
	fragment := string(before[start:])
	typed := strings.Fields(string(before[:start]))

	// `switch <name>` completes legacy transport names.
	if len(typed) > 0 && strings.ToLower(typed[0]) == "switch" && len(typed) == 1 {
		var names []string
		for _, e := range registry.GUITransports() {
			names = append(names, e.GUI.Name())
		}
		return suffixes(names, fragment), utf8.RuneCountInString(fragment)
	}

	cmd, consumed, path := c.reg.Resolve(typed)
	_ = path
	if cmd == nil {
		// Completing a group or top-level word: offer every child word of
		// the deepest resolved group, plus session aliases at top level.
		children := c.reg.Children(typed)
		if len(typed) == 0 {
			children = append(children, sessionAliasKeys(c.session)...)
			children = append(children, "switch")
		}
		return suffixes(children, fragment), utf8.RuneCountInString(fragment)
	}

	rest := typed[consumed:]
	// File paths complete after -f/--file/--out.
	if len(rest) > 0 {
		prev := rest[len(rest)-1]
		if prev == "-f" || prev == "--file" || prev == "--out" || prev == "-o" {
			return suffixes(candidateFiles(fragment), fragment), utf8.RuneCountInString(fragment)
		}
	}
	// Flag names complete after "--".
	if strings.HasPrefix(fragment, "--") {
		var names []string
		for _, f := range cmd.Flags {
			names = append(names, "--"+f.Name)
		}
		names = append(names, "--help")
		return suffixes(names, fragment), utf8.RuneCountInString(fragment)
	}
	// Positional value slots.
	argIndex := len(rest)
	kind := registry.ArgText
	if argIndex < len(cmd.Args) {
		kind = cmd.Args[argIndex]
	} else {
		kind = cmd.Variadic
	}
	return suffixes(c.candidates(kind), fragment), utf8.RuneCountInString(fragment)
}

func sessionAliasKeys(s *shellcmd.Session) []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.Aliases))
	for k := range s.Aliases {
		out = append(out, k)
	}
	return out
}

func (c *unifiedCompleter) candidates(kind registry.ArgKind) []string {
	switch kind {
	case registry.ArgPeer:
		seen := map[string]bool{}
		var out []string
		if c.session != nil {
			for _, p := range c.session.Peers {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
		if store, err := contacts.Load(); err == nil {
			for name := range store.Contacts {
				if !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
		return out
	case registry.ArgIdentity:
		matches, _ := filepath.Glob("*.json")
		var out []string
		for _, m := range matches {
			id := strings.TrimSuffix(filepath.Base(m), ".json")
			if id != "" && id != "contacts" {
				out = append(out, id)
			}
		}
		return out
	case registry.ArgThread:
		if c.session == nil || c.session.Identity == "" {
			return nil
		}
		store, err := mailbox.Load(c.session.Identity)
		if err != nil {
			return nil
		}
		var out []string
		for _, t := range store.List() {
			out = append(out, t.Key)
			if t.Title != "" {
				out = append(out, t.Title)
			}
		}
		return out
	default:
		return nil
	}
}

// candidateFiles completes local file paths for -f/--file style slots.
// Reserved for commands that opt in; unused slots stay silent.
func candidateFiles(fragment string) []string {
	dir, partial := filepath.Split(fragment)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(partial, ".") {
			continue
		}
		if strings.HasPrefix(name, partial) {
			if e.IsDir() {
				name += string(os.PathSeparator)
			}
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}
