package shellcmd

import (
	"strings"
	"testing"
)

func TestSplitLineQuotes(t *testing.T) {
	cases := []struct{ line, want string }{
		{`xfer send file "C:\\Users\\mahmo\\Desktop\\my file.png" to peer`, `xfer|send|file|C:\\Users\\mahmo\\Desktop\\my file.png|to|peer`},
		{`xfer send file 'C:\\Users\\mahmo\\Desktop\\my file.png' to peer`, `xfer|send|file|C:\\Users\\mahmo\\Desktop\\my file.png|to|peer`},
		{`xfer send file "C:\\Users\\mahmo\\Desktop\\repository-open-graph-template.png"`, `xfer|send|file|C:\\Users\\mahmo\\Desktop\\repository-open-graph-template.png`},
	}
	for _, tc := range cases {
		got, err := SplitLine(tc.line)
		if err != nil {
			t.Fatalf("SplitLine(%q): %v", tc.line, err)
		}
		if strings.Join(got, "|") != tc.want {
			t.Fatalf("SplitLine(%q) = %#v, want %q", tc.line, got, tc.want)
		}
	}
	if _, err := SplitLine(`xfer send file "unterminated`); err == nil {
		t.Fatal("unterminated quote must fail")
	}
}
func TestParseBasic(t *testing.T) {
	spec := []Flag{
		{Name: "to", Required: true},
		{Name: "file", Short: "f"},
		{Name: "json", IsBool: true},
		{Name: "limit", Default: "32"},
	}
	pos, vals, err := Parse([]string{"bob", "to", "alice", "file", "a.bin", "json", "limit", "10"}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 1 || pos[0] != "bob" {
		t.Fatalf("positionals: %v", pos)
	}
	if vals["to"] != "alice" || vals["file"] != "a.bin" || vals["json"] != "true" || vals["limit"] != "10" {
		t.Fatalf("values: %v", vals)
	}
}

func TestParseErrors(t *testing.T) {
	spec := []Flag{{Name: "to", Required: true}, {Name: "json", IsBool: true}}
	cases := [][]string{
		{"--bogus", "x"},
		{"-z"},
		{"to"},
		{},
		{"json", "maybe"},
	}
	for i, argv := range cases {
		if _, _, err := Parse(argv, spec); err == nil {
			t.Fatalf("case %d must fail", i)
		}
	}
	if _, _, _ = r.Resolve([]string{"nope"}); true {
		if cmd, _, _ := r.Resolve([]string{"nope"}); cmd != nil {
			t.Fatal("unknown must not resolve")
		}
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate must panic")
		}
	}()
	r := NewRegistry()
	r.Register([]string{"a"}, &Command{Name: "a"})
	r.Register([]string{"a"}, &Command{Name: "a"})
}

func TestSuggest(t *testing.T) {
	r := NewRegistry()
	r.Register([]string{"xfer", "send"}, &Command{Name: "send", Short: "s"})
	r.Register([]string{"xfer", "recv"}, &Command{Name: "recv", Short: "r"})
	r.Register([]string{"transport", "remove"}, &Command{Name: "remove", Short: "r"})
	got := Suggest(r, "snd")
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "send") {
		t.Fatalf("suggest snd: %v", got)
	}
	got = Suggest(r, "remove")
	if len(got) == 0 || got[0] != "remove" {
		t.Fatalf("exact must rank first: %v", got)
	}
	if got := Suggest(r, "zzzzzz"); len(got) != 0 {
		t.Fatalf("unrelated must stay quiet: %v", got)
	}
}

func TestSessionAlias(t *testing.T) {
	s := NewSession()
	if got := s.ExpandAlias([]string{"xsend", "a", "b"}); len(got) != 4 || got[0] != "xfer" || got[1] != "send" {
		t.Fatalf("alias: %v", got)
	}
	if got := s.ExpandAlias([]string{"unknown"}); len(got) != 1 {
		t.Fatalf("unknown: %v", got)
	}
	s.Aliases["loop"] = "loop"
	if got := s.ExpandAlias([]string{"loop", "x"}); got[0] != "loop" || len(got) != 2 {
		t.Fatalf("single expansion: %v", got)
	}
	s.RememberPeer("p1")
	s.RememberPeer("p1")
	if len(s.Peers) != 1 {
		t.Fatalf("dedupe: %v", s.Peers)
	}
	if !strings.Contains(s.Prompt(), "nextalk") {
		t.Fatalf("prompt: %q", s.Prompt())
	}
	s.Identity = "alicealice12"
	s.Relay = "relay1"
	if p := s.Prompt(); !strings.Contains(p, "relay1") {
		t.Fatalf("prompt env: %q", p)
	}
}

func TestSecretRedaction(t *testing.T) {
	if Secret("abc123", false) != Redacted {
		t.Fatal("must redact")
	}
	if Secret("abc123", true) != "abc123" {
		t.Fatal("must reveal when enabled")
	}
	if Secret("", false) != "" {
		t.Fatal("empty stays empty")
	}
}

func TestHelpText(t *testing.T) {
	c := &Command{
		Name: "send", Aliases: []string{"upload"}, Short: "Send it",
		Long: "Longer\ndocs.", ArgsUsage: "<peer>",
		Flags: []Flag{{Name: "to", Usage: "peer", Required: true}, {Name: "json", Usage: "json", IsBool: true}},
	}
	h := HelpText([]string{"xfer", "send"}, c)
	for _, want := range []string{"xfer send", "to <value>", "(required)", "upload", "Longer"} {
		if !strings.Contains(h, want) {
			t.Fatalf("help missing %q:\n%s", want, h)
		}
	}
	u := Usage([]string{"xfer", "send"}, c)
	if !strings.Contains(u, "to <value>") || !strings.Contains(u, "[json]") {
		t.Fatalf("usage: %q", u)
	}
}
