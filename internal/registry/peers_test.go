package registry

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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

func set(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func TestRememberPeerIgnoresPlaceholders(t *testing.T) {
	chdirTemp(t)
	s := &State{}

	// client.Client stores in-flight handshakes under these keys. They are not
	// peers and must never reach completion.
	for _, junk := range []string{"pending", "pending_somePeerID", "", "   "} {
		s.RememberPeer(junk)
	}

	if got := s.PeerCandidates(); len(got) != 0 {
		t.Fatalf("expected no candidates, got %v", got)
	}
}

func TestPeerCandidatesUnionsSources(t *testing.T) {
	chdirTemp(t)

	s := &State{Mailbox: map[string][]ChatMessage{
		"mailboxPeer": {{Body: "hi"}},
		"pending":     {{Body: "should be filtered"}},
	}}
	s.RememberPeer("connectedPeer")

	want := []string{"connectedPeer", "mailboxPeer"} // sorted
	if got := s.PeerCandidates(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PeerCandidates() = %v, want %v", got, want)
	}
}

func TestResolvePeerExactWinsOverPrefix(t *testing.T) {
	chdirTemp(t)

	s := &State{}
	s.RememberPeer("abc")
	s.RememberPeer("abcdef")

	// "abc" is a prefix of "abcdef" but also an exact known peer — the exact
	// match must win so a fully-typed ID is never reinterpreted.
	got, err := s.ResolvePeer("abc")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("ResolvePeer(%q) = %q, want %q", "abc", got, "abc")
	}
}

func TestResolvePeerUniquePrefix(t *testing.T) {
	chdirTemp(t)

	s := &State{}
	s.RememberPeer("uniquePeerLongID")

	got, err := s.ResolvePeer("uniq")
	if err != nil {
		t.Fatal(err)
	}
	if got != "uniquePeerLongID" {
		t.Fatalf("got %q, want expansion to the full ID", got)
	}
}

// TestResolvePeerRefusesAmbiguous is a safety test: silently picking one of
// several prefix matches would mean encrypting a message to the wrong peer.
func TestResolvePeerRefusesAmbiguous(t *testing.T) {
	chdirTemp(t)

	s := &State{}
	s.RememberPeer("sharedPrefixAAA")
	s.RememberPeer("sharedPrefixBBB")

	_, err := s.ResolvePeer("sharedPrefix")
	var ambiguous *AmbiguousPeerError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("expected *AmbiguousPeerError, got %T: %v", err, err)
	}
	if len(ambiguous.Matches) != 2 {
		t.Fatalf("expected both peers reported, got %v", ambiguous.Matches)
	}
}

func TestResolvePeerUnknownPassesThrough(t *testing.T) {
	chdirTemp(t)

	// A peer we've never talked to must still be addressable.
	got, err := (&State{}).ResolvePeer("brandNewPeerID")
	if err != nil {
		t.Fatal(err)
	}
	if got != "brandNewPeerID" {
		t.Fatalf("got %q, want passthrough", got)
	}
}

func TestResolvePeerEmpty(t *testing.T) {
	chdirTemp(t)
	if _, err := (&State{}).ResolvePeer("  "); !errors.Is(err, ErrEmptyPeer) {
		t.Fatalf("got %v, want ErrEmptyPeer", err)
	}
}

func TestIdentityCandidatesExcludesContacts(t *testing.T) {
	dir := chdirTemp(t)

	for _, name := range []string{"peerOne.json", "peerTwo.json", "contacts.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	got := set((&State{}).IdentityCandidates())

	for _, want := range []string{"peerOne", "peerTwo"} {
		if !got[want] {
			t.Fatalf("expected identity %q, got %v", want, got)
		}
	}
	if got["contacts"] {
		t.Error("contacts.json must not be treated as an identity")
	}
	if got["notes"] {
		t.Error("non-json files must be ignored")
	}
}

func TestCommandSpecArgKindAt(t *testing.T) {
	spec := CommandSpec{Name: "send", Args: []ArgKind{ArgPeer}, Variadic: ArgText}

	if spec.ArgKindAt(0) != ArgPeer {
		t.Error("arg 0 should be ArgPeer")
	}
	// Everything past the declared Args falls through to Variadic.
	for _, i := range []int{1, 2, 7} {
		if spec.ArgKindAt(i) != ArgText {
			t.Errorf("arg %d should be ArgText", i)
		}
	}
}

func TestFindCommandMatchesAliases(t *testing.T) {
	specs := []CommandSpec{{Name: "send", Aliases: []string{"encrypt"}}}

	if s, ok := FindCommand(specs, "encrypt"); !ok || s.Name != "send" {
		t.Fatalf("alias lookup failed: %+v ok=%v", s, ok)
	}
	if _, ok := FindCommand(specs, "nope"); ok {
		t.Error("expected miss for unknown command")
	}
}

func TestCommandNamesIncludesAliasesSorted(t *testing.T) {
	specs := []CommandSpec{
		{Name: "send", Aliases: []string{"encrypt"}},
		{Name: "init"},
	}

	want := []string{"encrypt", "init", "send"}
	if got := CommandNames(specs); !reflect.DeepEqual(got, want) {
		t.Fatalf("CommandNames() = %v, want %v", got, want)
	}
}
