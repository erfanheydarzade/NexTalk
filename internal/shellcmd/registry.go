package shellcmd

import (
	"fmt"
	"sort"
	"strings"
)

// Registry is the command tree. Groups are plain path prefixes —
// "transport register" and "xfer send" live side by side, and future
// transports register their own subtrees without touching this file.
type Registry struct {
	roots map[string]*node
	order []string // first-registration order for stable help listings
}

type node struct {
	cmd      *Command
	children map[string]*node
	order    []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{roots: map[string]*node{}}
}

// Register adds cmd at path (e.g. "transport", "register"). Intermediate
// nodes are created as pure groups. Registering the same full path twice
// panics — like the transport registry, misconfiguration fails loudly.
func (r *Registry) Register(path []string, cmd *Command) {
	if len(path) == 0 {
		panic("shellcmd: empty command path")
	}
	m := r.roots
	var n *node
	for _, word := range path {
		word = strings.ToLower(word)
		child, ok := m[word]
		if !ok {
			child = &node{children: map[string]*node{}}
			m[word] = child
		}
		n = child
		m = child.children
	}
	if n.cmd != nil {
		panic(fmt.Sprintf("shellcmd: duplicate command %q", strings.Join(path, " ")))
	}
	n.cmd = cmd
	r.order = append(r.order, strings.Join(path, " "))
}

// Resolve walks words down the tree, matching names and aliases at every
// level. It returns the deepest command found, how many words it consumed,
// and the full path. A prefix that names only a group resolves to nil with
// the group path, so callers can list that group's children.
func (r *Registry) Resolve(words []string) (cmd *Command, consumed int, path []string) {
	m := r.roots
	for _, w := range words {
		w = strings.ToLower(w)
		var next *node
		for name, child := range m {
			if name == w {
				next = child
				path = append(path, name)
				break
			}
			if child.cmd != nil {
				for _, a := range child.cmd.Aliases {
					if strings.ToLower(a) == w {
						next = child
						path = append(path, name)
						break
					}
				}
				if next != nil {
					break
				}
			}
		}
		if next == nil {
			break
		}
		consumed++
		if next.cmd != nil {
			cmd = next.cmd
		}
		m = next.children
	}
	return cmd, consumed, path
}

// Children lists the immediate subcommand names under path ("" = top level).
func (r *Registry) Children(path []string) []string {
	m := r.roots
	for _, w := range path {
		child, ok := m[strings.ToLower(w)]
		if !ok {
			return nil
		}
		m = child.children
	}
	var out []string
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TopLevel lists every registered full path in registration order.
func (r *Registry) TopLevel() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r.order {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// AllCommands returns every leaf command with its path.
func (r *Registry) AllCommands() (paths [][]string, cmds []*Command) {
	var walk func(prefix []string, m map[string]*node)
	walk = func(prefix []string, m map[string]*node) {
		names := make([]string, 0, len(m))
		for name := range m {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child := m[name]
			p := append(append([]string{}, prefix...), name)
			if child.cmd != nil {
				paths = append(paths, p)
				cmds = append(cmds, child.cmd)
			}
			walk(p, child.children)
		}
	}
	walk(nil, r.roots)
	return paths, cmds
}
