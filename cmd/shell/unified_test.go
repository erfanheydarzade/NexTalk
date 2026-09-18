package shell

import (
	"strings"
	"testing"

	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
	"github.com/fatih/color"
)

func testRegistry(t *testing.T) *shellcmd.Registry {
	t.Helper()
	return buildRegistry()
}

func runLine(t *testing.T, reg *shellcmd.Registry, s *shellcmd.Session, line string) (string, string, error) {
	t.Helper()
	var stdout, stderr strings.Builder
	err := execute(reg, s, line, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func TestExecuteHelp(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	stdout, stderr, err := runLine(t, reg, s, "help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "xfer") || !strings.Contains(stderr, "transport") {
		t.Fatalf("top help must list groups: %q", stderr)
	}
	if stdout != "" {
		t.Fatalf("help is UI, must not touch stdout: %q", stdout)
	}
	_, stderr, err = runLine(t, reg, s, "help xfer send")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--to", "--file", "Usage:"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("xfer send help missing %q:\n%s", want, stderr)
		}
	}
}

func TestExecuteUnknownSuggests(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	_, _, err := runLine(t, reg, s, "xfer snd")
	if err == nil || !strings.Contains(err.Error(), "xfer send") {
		t.Fatalf("must suggest xfer send: %v", err)
	}
	_, _, err = runLine(t, reg, s, "zzzznothing")
	if err == nil || strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("unrelated must stay quiet-ish: %v", err)
	}
	_, _, err = runLine(t, reg, s, "transport")
	if err == nil || !strings.Contains(err.Error(), "incomplete command") {
		t.Fatalf("bare group must list children: %v", err)
	}
}

func TestExecuteAlias(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	// xsend is a default alias for "xfer send"; it must fail on missing
	// --file (proving the alias expanded and dispatched), not on dispatch.
	_, _, err := runLine(t, reg, s, "xsend --file f.bin --to p")
	if err == nil {
		t.Fatal("expected a downstream error, proving alias dispatch worked")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("alias did not expand: %v", err)
	}
}

func TestSessionCommands(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	if _, _, err := runLine(t, reg, s, "alias ll xfer list"); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runLine(t, reg, s, "ll --json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "transfers") {
		t.Fatalf("alias ll must reach xfer list json: %q", stdout)
	}
	if _, _, err := runLine(t, reg, s, "use relay relay1"); err != nil {
		t.Fatal(err)
	}
	if s.Relay != "relay1" {
		t.Fatalf("relay not set: %+v", s)
	}
	if !strings.Contains(s.Prompt(), "relay1") {
		t.Fatalf("prompt missing relay: %q", s.Prompt())
	}
	_, _, err = runLine(t, reg, s, "context")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = runLine(t, reg, s, "use bogus x")
	if err == nil {
		t.Fatal("use bogus must fail")
	}
}

func TestRunScriptExitCodes(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	var stdout, stderr strings.Builder
	code := RunScript(reg, s, strings.NewReader("alias\ncontext\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("clean script must exit 0, got %d (%s)", code, stderr.String())
	}
	if len(s.History) != 2 {
		t.Fatalf("history: %v", s.History)
	}
	s2 := shellcmd.NewSession()
	var stdout2, stderr2 strings.Builder
	code = RunScript(reg, s2, strings.NewReader("zzzznothing\ncontext\n"), &stdout2, &stderr2)
	if code != 1 {
		t.Fatalf("failing script must exit 1, got %d", code)
	}
	if !strings.Contains(stderr2.String(), "unknown command") {
		t.Fatalf("error must surface on stderr: %q", stderr2.String())
	}
	if stdout2.String() != "" {
		t.Fatalf("failing lines must not pollute stdout: %q", stdout2.String())
	}
	// Comments and blanks are skipped, exit is clean.
	s3 := shellcmd.NewSession()
	var stdout3, stderr3 strings.Builder
	code = RunScript(reg, s3, strings.NewReader("# comment\n\nexit\ncontext\n"), &stdout3, &stderr3)
	if code != 0 {
		t.Fatalf("exit script must be 0, got %d", code)
	}
	if len(s3.History) != 1 {
		t.Fatalf("only exit recorded: %v", s3.History)
	}
}

func TestFlagErrorsClear(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	_, _, err := runLine(t, reg, s, "transport attach --mailbox abc")
	if err == nil || !strings.Contains(err.Error(), "--shard") {
		t.Fatalf("missing required flag must name it: %v", err)
	}
	_, _, err = runLine(t, reg, s, "transport poll --bogus 1")
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("unknown flag must name it: %v", err)
	}
}

func TestUnifiedCompleter(t *testing.T) {
	reg := testRegistry(t)
	s := shellcmd.NewSession()
	c := newUnifiedCompleter(s, reg)

	complete := func(line string) []string {
		runes := []rune(line)
		raw, _ := c.Do(runes, len(runes))
		var out []string
		for _, r := range raw {
			out = append(out, string(r))
		}
		return out
	}

	got := strings.Join(complete("x"), ",")
	if !strings.Contains(got, "fer ") {
		t.Fatalf("x must offer xfer: %q", got)
	}
	got = strings.Join(complete("xfer "), ",")
	for _, want := range []string{"send", "recv", "inspect"} {
		if !strings.Contains(got, want) {
			t.Fatalf("xfer children missing %q: %q", want, got)
		}
	}
	got = strings.Join(complete("xfer send --"), ",")
	if !strings.Contains(got, "to ") || !strings.Contains(got, "file ") {
		t.Fatalf("flag completion: %q", got)
	}
	// Aliases complete at top level too (suffix after the fragment).
	got = strings.Join(complete("xs"), ",")
	if !strings.Contains(got, "end ") {
		t.Fatalf("alias completion: %q", got)
	}
}

func TestPromptForIsReadlineSafe(t *testing.T) {
	// Regression test: readline redraws its prompt on every keystroke and
	// miscounts embedded newlines, repeating the prompt once per typed
	// character. ANSI colors are fine (readline strips them via
	// runes.ColorFilter when measuring width), but the input prompt must
	// stay single-line and must visibly remain "╰─❯ ".
	for _, session := range []*shellcmd.Session{
		nil,
		shellcmd.NewSession(),
		{Identity: "alicealice12", Relay: "filerelay"},
	} {
		contextLine, inputPrompt := promptFor(session)
		if contextLine == "" {
			t.Fatal("context line must never be empty")
		}
		if strings.Contains(inputPrompt, "\n") {
			t.Fatalf("input prompt must be single-line: %q", inputPrompt)
		}
		if !strings.Contains(inputPrompt, "╰─❯") {
			t.Fatalf("input prompt must contain ╰─❯: %q", inputPrompt)
		}
	}
}

func TestPromptLinesShareOneColor(t *testing.T) {
	// Regression test for "╭─ sky blue but ╰─❯ white": the context line
	// (╭─[…], printed with fmt) and the readline-owned input arrow (╰─❯)
	// must open with the same escape sequence, so no rendering engine can
	// paint them differently.
	old := color.NoColor
	color.NoColor = false
	defer func() { color.NoColor = old }()

	arrow := ui.InputArrow()
	context := shellcmd.NewSession().PromptColored()
	open := func(s string) string {
		i := strings.Index(s, "\x1b[")
		if i < 0 {
			return ""
		}
		j := strings.Index(s[i:], "m")
		if j < 0 {
			return ""
		}
		return s[i : i+j+1]
	}
	if open(arrow) == "" || open(context) == "" {
		t.Fatalf("both prompt lines must be colored: arrow=%q context=%q", arrow, context)
	}
	if open(arrow) != open(context) {
		t.Fatalf("prompt color mismatch: ╰─❯ opens with %q but ╭─ opens with %q", open(arrow), open(context))
	}
}

func TestReadlineUsesSharedWriter(t *testing.T) {
	// The context line goes through ui.ConsoleOut while readline renders
	// the input arrow; if readline writes to a different engine (its
	// built-in Windows ANSI emulator), bold SGR combos render white there
	// and sky blue on the context line. Both configs must share the writer.
_unified := buildRegistry()
	_ = _unified
	cfg := readlineConfig(&RuntimeState{}, &fakeTransport{})
	if cfg.Stdout != ui.ConsoleOut {
		t.Fatal("legacy readline Stdout must be ui.ConsoleOut")
	}
	if cfg.Stderr != ui.ConsoleOut {
		t.Fatal("legacy readline Stderr must be ui.ConsoleOut")
	}
}
