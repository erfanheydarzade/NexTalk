// Package shellcmd is the modular command framework behind the NexTalk
// interactive shell. Commands are plain structs that self-register into a
// tree — no switch/case dispatcher anywhere:
//
//	transport
//	├── register
//	├── list
//	├── remove
//	└── status
//	xfer
//	├── send
//	├── recv
//	├── resume
//	├── cancel
//	└── inspect
//
// Every command declares its name, aliases, description, arguments, flags,
// and handler. The same registry drives execution, `help` rendering, Tab
// completion, and did-you-mean suggestions, so those can never disagree
// about what exists.
package shellcmd

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// Flag describes one `--name value` / `-n value` / `--bool` option.
type Flag struct {
	// Name is the long form without dashes, e.g. "transports-dir".
	Name string
	// Short is the single-letter form without the dash, e.g. "i".
	Short string
	// Usage is the one-line help text.
	Usage string
	// Default applies when the flag is absent.
	Default string
	// Required fails parsing when the flag is absent and empty.
	Required bool
	// IsBool makes the flag a switch: bare presence means "true".
	IsBool bool
}

// Command is one shell command. Run receives everything parsed; output goes
// to ctx.Stdout (machine-readable) and ctx.Stderr (human UI).
type Command struct {
	// Name is the primary word, e.g. "send".
	Name string
	// Aliases are alternative spellings resolved before dispatch.
	Aliases []string
	// Short is the one-line summary used in listings.
	Short string
	// Long is the detailed help body. May include an example block.
	Long string
	// ArgsUsage documents positionals, e.g. "<peer> <msg...>".
	ArgsUsage string
	// MinArgs bounds the minimum positional count.
	MinArgs int
	// MaxArgs bounds the maximum positional count. Zero or negative means
	// unbounded — commands validate their own arity in Run when it matters.
	MaxArgs int
	// Args declares the completion kind of each positional slot
	// (registry.ArgPeer, ArgIdentity, ...). Slots beyond the list use
	// Variadic. Pure metadata for completion — handlers validate.
	Args []registry.ArgKind
	// Variadic is the kind for arguments past Args.
	Variadic registry.ArgKind
	// Complete, when non-nil, fully owns candidate selection (mirrors
	// registry.CommandSpec.Complete but receives the shell session).
	Complete func(s *Session, typed []string, argIndex int, fragment string) []string
	// Flags accepted by this command.
	Flags []Flag
	// Run executes the command. Returning an error prints a clear message
	// and (in scripting mode) sets a nonzero exit code.
	Run func(ctx *Context) error
}

// Names returns the primary name plus every alias.
func (c *Command) Names() []string {
	return append([]string{c.Name}, c.Aliases...)
}

// Context carries everything a command handler needs. Frontends (the
// interactive shell and one-shot scripting) fill it in identically, so
// handlers never know which frontend invoked them.
type Context struct {
	// Session is the live shell session (identity, relay, aliases...).
	// Never nil inside the shell; CLI shims pass a throwaway session.
	Session *Session
	// Args are positional arguments after flag parsing.
	Args []string
	// Flags maps long flag names to their parsed values.
	Flags map[string]string
	// Stdout carries machine-readable output. Never human UI.
	Stdout io.Writer
	// Stderr carries logs and human UI. Never machine output.
	Stderr io.Writer
}

// Get returns a flag value or its default ("").
func (c *Context) Get(name string) string {
	if c.Flags == nil {
		return ""
	}
	return c.Flags[name]
}

// Bool reports whether a boolean flag was passed.
func (c *Context) Bool(name string) bool {
	v, ok := c.Flags[name]
	if !ok {
		return false
	}
	return v == "true" || v == "1" || v == "yes"
}

// Need returns an error naming the missing required argument.
func (c *Context) Need(n int, what string) error {
	if len(c.Args) <= n {
		return fmt.Errorf("missing %s", what)
	}
	return nil
}

// JSON reports whether machine-readable output was requested.
func (c *Context) JSON() bool {
	return c.Bool("json") || (c.Session != nil && c.Session.JSON)
}

// ShowSecrets reports whether secret values may be printed verbatim.
// Default is redaction; only an explicit --show-secrets opts in.
func (c *Context) ShowSecrets() bool {
	return c.Bool("show-secrets") || (c.Session != nil && c.Session.ShowSecrets)
}

// Usage renders the one-line synopsis for a command at path.
func Usage(path []string, c *Command) string {
	var sb strings.Builder
	sb.WriteString(strings.Join(path, " "))
	if c.ArgsUsage != "" {
		sb.WriteString(" " + c.ArgsUsage)
	}
	for _, f := range c.Flags {
		if f.IsBool {
			fmt.Fprintf(&sb, " [--%s]", f.Name)
			continue
		}
		fmt.Fprintf(&sb, " [--%s value]", f.Name)
	}
	return sb.String()
}

// HelpText renders full help for a command, with a colorized Usage header,
// section titles and flag names. Plain substrings ("Usage:", "--to",
// "(required)", aliases, Long) are preserved so scripts/tests can still
// match on them; colors are no-ops when piped.
func HelpText(path []string, c *Command) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\n\n", ui.Title.Sprint("Usage:"), ui.Code.Sprint(Usage(path, c)))
	sb.WriteString(c.Short + "\n")
	if c.Long != "" {
		sb.WriteString("\n" + strings.TrimSpace(c.Long) + "\n")
	}
	if len(c.Aliases) > 0 {
		fmt.Fprintf(&sb, "\n%s %s\n", ui.Title.Sprint("Aliases:"), ui.Code.Sprint(strings.Join(c.Aliases, ", ")))
	}
	if len(c.Flags) > 0 {
		sb.WriteString("\n" + ui.Title.Sprint("Flags:") + "\n")
		names := make([]Flag, len(c.Flags))
		copy(names, c.Flags)
		sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
		for _, f := range names {
			short := ""
			if f.Short != "" {
				short = ", -" + f.Short
			}
			req := ""
			if f.Required {
				req = " (required)"
			}
			def := ""
			if f.Default != "" && !f.IsBool {
				def = fmt.Sprintf(" (default %q)", f.Default)
			}
			reqColored := ""
			if req != "" {
				reqColored = ui.Warning.Sprint(req)
			}
			fmt.Fprintf(&sb, "  %s%s  %s%s%s\n", ui.Code.Sprint("--"+f.Name+short), "", f.Usage, reqColored, ui.Comment.Sprint(def))
			// Keep a plain copy of the required marker for substring
			// matching (colors wrap it above): the raw text is already
			// embedded in the colored spans' content.
		}
	}
	return sb.String()
}
