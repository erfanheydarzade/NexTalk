// Package transportops holds the shared operation implementations behind
// every transport user interface. The cobra commands under cmd/transport and
// the interactive shell (cmd/shell) are both thin frontends over these
// functions — the shell is just another frontend, and behavior can never
// drift between the two.
//
// Output policy (repo-wide rule): machine-readable output goes to Stdout,
// human UI and logs go to Stderr. Secrets (read_secret bearers, download
// tickets, private keys, scoped credentials) print redacted unless the
// caller explicitly opts in with ShowSecrets.
package transportops

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	ntx "github.com/erfanheydarzade/NexTalk/internal/transport"
)

// Deps carries everything an operation needs. Frontends fill it in
// identically; operations never know which frontend invoked them.
type Deps struct {
	// TransportsDir overrides the transport manager directory ("" = default).
	TransportsDir string
	// Stdout carries machine-readable output. Never human UI.
	Stdout io.Writer
	// Stderr carries logs and human UI. Never machine output.
	Stderr io.Writer
	// JSON selects machine-readable output on Stdout.
	JSON bool
	// ShowSecrets disables secret redaction. Off unless explicitly requested.
	ShowSecrets bool
	// Session is the live shell session (may be nil for one-shot CLI use).
	// Used for identity/relay defaults and recording transfers.
	Session *shellcmd.Session
	// PromptSecret reads a secret without echoing (hidden input). Shell
	// wires readline.Password; one-shot CLI leaves it nil and requires the
	// corresponding flag instead.
	PromptSecret func(prompt string) (string, error)
	// Confirm asks a yes/no question. Nil means auto-yes (one-shot CLI).
	Confirm func(prompt string) (bool, error)
	// manager caches the opened transport manager per Deps.
	manager *ntx.Manager
}

// Ctx returns a context with a generous default timeout.
func (d *Deps) Ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// Manager opens (and caches) the transport manager.
func (d *Deps) Manager() (*ntx.Manager, error) {
	if d.manager != nil {
		return d.manager, nil
	}
	m, err := ntx.NewManager(d.TransportsDir)
	if err != nil {
		return nil, err
	}
	d.manager = m
	return m, nil
}

// JSONOut writes one machine-readable document to Stdout.
func (d *Deps) JSONOut(v any) error {
	return shellcmd.WriteJSON(d.Stdout, v)
}

// Human writes a human-UI line to Stderr.
func (d *Deps) Human(format string, args ...any) {
	shellcmd.Human(d.Stderr, format, args...)
}

// Secret renders a secret value honoring the redaction policy.
func (d *Deps) Secret(v string) string {
	return shellcmd.Secret(v, d.ShowSecrets)
}

// ConfirmOr asks Confirm, defaulting to yes when no prompter is wired
// (one-shot CLI stays non-interactive).
func (d *Deps) ConfirmOr(prompt string) (bool, error) {
	if d.Confirm == nil {
		return true, nil
	}
	return d.Confirm(prompt)
}

// SecretOr asks PromptSecret, falling back to flag when unwired.
func (d *Deps) SecretOr(flagValue, prompt string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if d.PromptSecret == nil {
		return "", fmt.Errorf("a secret is required: pass the flag or run inside the shell")
	}
	v, err := d.PromptSecret(prompt)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("empty secret")
	}
	return v, nil
}
