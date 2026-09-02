// internal/registry/completion.go
//
// Completion metadata lives in the registry (not in cmd/shell) for the same
// reason State does: transports must be able to describe their own command
// surface without importing cmd/shell, which would create an import cycle.
//
// A transport opts in by implementing CompletionProvider. The shell's readline
// completer type-asserts for it, so transports that don't implement it still
// work — they just fall back to the base command set.
package registry

import (
	"fmt"
	"sort"

	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// ArgKind describes what a single positional argument accepts, which is all the
// completer needs to know to offer candidates for that slot.
type ArgKind int

const (
	// ArgText is free-form text (message bodies, pasted JSON) — no completion.
	ArgText ArgKind = iota
	// ArgPeer is a peer ID or a contacts alias that resolves to one.
	ArgPeer
	// ArgIdentity is a local identity `load` can take, i.e. a <id>.json profile
	// in the current working directory.
	ArgIdentity
	// ArgContext is a multi-message context ID that `context` subcommands take.
	ArgContext
	// ArgThread is anything `mailbox` accepts: a peer, a contacts alias, a
	// group context ID, or a group display name.
	ArgThread
)

// CommandSpec describes one command inside a transport sub-shell: its name, any
// alternative spellings, and the kind of each positional argument.
//
// Args covers the fixed leading arguments; Variadic covers everything after
// them (so `send <peer> <msg...>` is Args{ArgPeer} + Variadic ArgText). An
// optional trailing argument is just listed in Args — specs only pick
// candidates, they never validate, so an unused slot costs nothing.
type CommandSpec struct {
	Name     string
	Aliases  []string
	Args     []ArgKind
	Variadic ArgKind
	Usage    string
	Help     string

	// Complete, when non-nil, fully owns candidate selection for this
	// command's arguments. It replaces the Args/Variadic mapping entirely —
	// use it when a command's slots depend on earlier words, e.g.
	// `context add <ctx> <peer>` completing contexts then peers while
	// `context create` takes a free-form name.
	//
	// typed holds every word after the command name itself (so for the
	// line "context add abc de", typed is ["add","abc","de"]); argIndex is
	// the position being completed and fragment == typed[argIndex] when in
	// range. Return nil for "no candidates".
	Complete func(s *State, typed []string, argIndex int, fragment string) []string
}

// ArgKindAt returns the ArgKind for positional argument i (0-based, excluding
// the command word itself).
func (c CommandSpec) ArgKindAt(i int) ArgKind {
	if i < len(c.Args) {
		return c.Args[i]
	}
	return c.Variadic
}

// Names returns the command's primary name plus every alias.
func (c CommandSpec) Names() []string {
	return append([]string{c.Name}, c.Aliases...)
}

// usage is the Usage string, defaulting to the bare command name.
func (c CommandSpec) usage() string {
	if c.Usage != "" {
		return c.Usage
	}
	return c.Name
}

// CompletionProvider is the optional interface a GUITransport implements to
// describe its own commands to the shell completer and help renderer.
type CompletionProvider interface {
	Commands() []CommandSpec
}

// BaseCommands are the commands every transport sub-shell handles. Transports
// append their own specs to these so help/switch/exit never have to be
// re-declared (or accidentally omitted from completion).
func BaseCommands() []CommandSpec {
	return []CommandSpec{
		{Name: "help", Help: "Show this command list"},
		{Name: "switch", Aliases: []string{"exit"}, Usage: "switch / exit", Help: "Return to the main menu"},
	}
}

func IdentityCommand(help string) CommandSpec {
	return CommandSpec{
		Name:  "load",
		Args:  []ArgKind{ArgIdentity},
		Usage: "load <id>",
		Help:  help,
	}
}

func PeersCommand() CommandSpec {
	return CommandSpec{
		Name: "peers",
		Help: "List every peer ID this shell can complete",
	}
}

func MessageCommand(name string, aliases ...string) CommandSpec {
	return CommandSpec{
		Name:     name,
		Aliases:  aliases,
		Args:     []ArgKind{ArgPeer},
		Variadic: ArgText,
		Usage:    name + " <peer> <msg>",
	}
}

// CommandsOf returns the spec list for t, falling back to BaseCommands for a
// transport that hasn't implemented CompletionProvider.
func CommandsOf(t GUITransport) []CommandSpec {
	if p, ok := t.(CompletionProvider); ok {
		return p.Commands()
	}
	return BaseCommands()
}

// FindCommand looks up a spec by primary name or alias.
func FindCommand(specs []CommandSpec, name string) (CommandSpec, bool) {
	for _, s := range specs {
		for _, n := range s.Names() {
			if n == name {
				return s, true
			}
		}
	}
	return CommandSpec{}, false
}

// CommandNames returns every completable command word (primary names and
// aliases), sorted and deduplicated.
func CommandNames(specs []CommandSpec) []string {
	set := make(map[string]bool, len(specs)*2)
	for _, s := range specs {
		for _, n := range s.Names() {
			if n != "" {
				set[n] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RenderHelp prints the spec list as an aligned table. Transports call this
// from Help() so help text can never drift from what completion offers.
func RenderHelp(specs []CommandSpec) {
	width := 0
	for _, s := range specs {
		if n := len(s.usage()); n > width {
			width = n
		}
	}

	fmt.Printf("\n%s\n", ui.Bold.Sprint("Commands:"))
	for _, s := range specs {
		fmt.Printf("  %-*s  - %s\n", width, s.usage(), s.Help)
	}
	fmt.Printf("\n%s press Tab to complete commands, peer IDs, contact aliases\n", ui.Bold.Sprint("Tip:"))
	fmt.Println("     and local identities. Press Tab twice to list all candidates.")
}
