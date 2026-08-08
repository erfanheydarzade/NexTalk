package shell

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

// fakeTransport is a minimal GUITransport declaring a command surface that
// covers every ArgKind, so the completer can be tested without a relay or real
// key generation.
type fakeTransport struct{}

func (f *fakeTransport) Name() string                                   { return "fake" }
func (f *fakeTransport) MenuLabel() string                              { return "Fake" }
func (f *fakeTransport) Init(*registry.State) error                     { return nil }
func (f *fakeTransport) Execute(*registry.State, string, []string) bool { return true }
func (f *fakeTransport) Help()                                          {}

func (f *fakeTransport) Commands() []registry.CommandSpec {
	return append([]registry.CommandSpec{
		{Name: "init"},
		registry.IdentityCommand(""),
		{Name: "connect", Args: []registry.ArgKind{registry.ArgPeer}},
		{Name: "listen"},
		registry.MessageCommand("send", "encrypt"),
		{Name: "mailbox", Args: []registry.ArgKind{registry.ArgPeer}},
	}, registry.BaseCommands()...)
}

// complete runs the completer over line (cursor at end) and returns the fully
// completed words — fragment + each suffix, trailing space trimmed. Asserting
// on whole words keeps tests readable while still exercising the offset
// arithmetic, which it verifies on the way through.
func complete(t *testing.T, c *shellCompleter, line string) []string {
	t.Helper()

	runes := []rune(line)
	suffixes, length := c.Do(runes, len(runes))

	fragment := line
	if i := strings.LastIndexAny(line, " \t"); i >= 0 {
		fragment = line[i+1:]
	}
	if want := len([]rune(fragment)); length != want && len(suffixes) > 0 {
		t.Fatalf("Do(%q) length = %d, want fragment rune count %d", line, length, want)
	}

	out := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		out = append(out, fragment+strings.TrimSuffix(string(s), " "))
	}
	return out
}

func newTestCompleter(state *registry.State) *shellCompleter {
	return newShellCompleter(state, &fakeTransport{})
}

// chdirTemp isolates identity/contacts discovery, which reads the CWD.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	// Registered after TempDir's own cleanup so it runs first (LIFO): Windows
	// refuses to delete a directory that is a process's CWD.
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

func TestCompleteCommandNames(t *testing.T) {
	chdirTemp(t)
	c := newTestCompleter(&registry.State{})

	// "enc" proves aliases are completable too — encrypt is an alias of send.
	for line, want := range map[string]string{"co": "connect", "enc": "encrypt"} {
		if got := complete(t, c, line); !slices.Contains(got, want) {
			t.Errorf("completing %q: want %q in %v", line, want, got)
		}
	}

	all := complete(t, c, "") // empty line lists everything declared
	for _, want := range []string{"init", "load", "connect", "listen", "send", "mailbox", "help", "switch", "exit"} {
		if !slices.Contains(all, want) {
			t.Errorf("want %q in full command list %v", want, all)
		}
	}
}

// TestCompletePeerAfterConnect is the regression test for the reported bug: a
// peer ID only ever passed to `connect` must be completable afterwards, even
// though no message was exchanged and Mailbox is empty.
func TestCompletePeerAfterConnect(t *testing.T) {
	chdirTemp(t)

	const peerID = "t_id_9wLmQ2ZxFakeButLongEnoughToNeedCompletion"
	state := &registry.State{}
	state.RememberPeer(peerID) // what the connect handler now does

	if len(state.Mailbox) != 0 {
		t.Fatal("precondition failed: Mailbox should still be empty")
	}

	c := newTestCompleter(state)

	// The last case is an empty peer slot: one Tab must still offer the peer.
	for _, line := range []string{"connect t_", "send t_", "encrypt t_", "mailbox t_", "send "} {
		if got := complete(t, c, line); !slices.Contains(got, peerID) {
			t.Errorf("completing %q: want peer %q in %v", line, peerID, got)
		}
	}
}

func TestNoCompletionWhereItWouldBeWrong(t *testing.T) {
	chdirTemp(t)

	const peerID = "peerAAAAAAAAAAAAAAAAAAAAAAAA"
	state := &registry.State{}
	state.RememberPeer(peerID)
	c := newTestCompleter(state)

	cases := map[string]string{
		"message body is free text":   "send " + peerID + " pe",
		"unknown command has no args": "bogus pe",
	}
	for name, line := range cases {
		if got := complete(t, c, line); len(got) != 0 {
			t.Errorf("%s: completing %q returned %v, want nothing", name, line, got)
		}
	}
}

func TestCompleteIdentityFromCwd(t *testing.T) {
	dir := chdirTemp(t)

	const identity = "identityAAAA1111"
	// contacts.json is the address book, not an identity — must be excluded.
	for _, name := range []string{identity + ".json", "contacts.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	got := complete(t, newTestCompleter(&registry.State{}), "load ")

	if !slices.Contains(got, identity) {
		t.Errorf("want identity %q in %v", identity, got)
	}
	if slices.Contains(got, "contacts") {
		t.Errorf("contacts.json must not be offered as an identity: %v", got)
	}
}

// TestCompleteOffsetIsRuneCount guards the readline contract: the returned
// length is a rune count, not a byte count. A byte count would corrupt the input
// line for multi-byte fragments.
func TestCompleteOffsetIsRuneCount(t *testing.T) {
	chdirTemp(t)

	state := &registry.State{}
	state.RememberPeer("日本peer1234")
	c := newTestCompleter(state)

	line := []rune("connect 日本")
	suffixes, length := c.Do(line, len(line))

	if len(suffixes) == 0 {
		t.Fatal("expected a candidate for a multi-byte prefix")
	}
	if length != 2 {
		t.Errorf("length = %d, want 2 runes (not %d bytes)", length, len("日本"))
	}
	if got := string(suffixes[0]); got != "peer1234 " {
		t.Errorf("suffix = %q, want %q", got, "peer1234 ")
	}
}
