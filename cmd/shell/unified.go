package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// execute runs one input line through alias expansion, the command tree,
// and the shared handlers. It returns a sentinel error for exit.
func execute(reg *shellcmd.Registry, session *shellcmd.Session, line string, stdout, stderr io.Writer) error {
	words := strings.Fields(line)
	if len(words) == 0 {
		return nil
	}
	words = session.ExpandAlias(words)

	cmd, consumed, path := reg.Resolve(words)
	if cmd == nil {
		// A mistyped leaf inside a group ("xfer snd") deserves a
		// suggestion, not just the child listing. Leaf hits render with
		// their group path so the fix is copy-pasteable.
		if consumed < len(words) {
			if sug := shellcmd.Suggest(reg, words[consumed]); len(sug) > 0 {
				children := map[string]bool{}
				for _, c := range reg.Children(path) {
					children[c] = true
				}
				for i, s := range sug {
					if children[s] {
						sug[i] = strings.Join(append(append([]string{}, path...), s), " ")
					}
				}
				return fmt.Errorf("unknown command %q; did you mean: %s?",
					strings.Join(words, " "), strings.Join(sug, ", "))
			}
		}
		if len(path) > 0 {
			return fmt.Errorf("incomplete command %q — subcommands: %s (try `help %s`)",
				strings.Join(words, " "), strings.Join(reg.Children(path), ", "), strings.Join(path, " "))
		}
		if sug := shellcmd.Suggest(reg, words[0]); len(sug) > 0 {
			return fmt.Errorf("unknown command %q; did you mean: %s?", words[0], strings.Join(sug, ", "))
		}
		return fmt.Errorf("unknown command %q (try `help`)", words[0])
	}
	rest := words[consumed:]
	// --help/-h anywhere shows command help instead of executing. Handled
	// before flag parsing so help never trips on other flags.
	for _, w := range rest {
		if w == "--help" || w == "-h" {
			fmt.Fprintln(stderr, shellcmd.HelpText(path, cmd))
			return nil
		}
	}
	positional, values, err := shellcmd.Parse(rest, cmd.Flags)
	if err != nil {
		return fmt.Errorf("%s: %v", strings.Join(path, " "), err)
	}
	if v, ok := values["help"]; ok && (v == "true" || v == "1") {
		fmt.Fprintln(stderr, shellcmd.HelpText(path, cmd))
		return nil
	}
	if cmd.MinArgs > 0 && len(positional) < cmd.MinArgs {
		return fmt.Errorf("usage: %s", shellcmd.Usage(path, cmd))
	}
	if cmd.MaxArgs > 0 && len(positional) > cmd.MaxArgs {
		return fmt.Errorf("too many arguments: usage: %s", shellcmd.Usage(path, cmd))
	}
	ctx := &shellcmd.Context{
		Session: session, Args: positional, Flags: values,
		Stdout: stdout, Stderr: stderr,
	}
	if err := cmd.Run(ctx); err != nil {
		if err == errExitShell {
			return err
		}
		return fmt.Errorf("%s: %v", strings.Join(path, " "), err)
	}
	return nil
}

// isTerminal reports whether stdin is an interactive terminal. Piped stdin
// means scripting mode: every line runs non-interactively with exit codes.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// RunScript executes lines from r one at a time and returns the process
// exit code: 0 when every line succeeded, 1 otherwise. Output policy is
// identical to interactive mode; only the prompt and colors differ.
// `switch` is interactive-only and fails here with a clear error.
func RunScript(reg *shellcmd.Registry, session *shellcmd.Session, r io.Reader, stdout, stderr io.Writer) int {
	code := 0
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first := strings.ToLower(strings.Fields(line)[0])
		if first == "switch" {
			fmt.Fprintf(stderr, "  %s %s\n", ui.Fail.Sprint("[✗]"), "`switch` is interactive-only")
			code = 1
			continue
		}
		session.History = append(session.History, line)
		if err := execute(reg, session, line, stdout, stderr); err != nil {
			if err == errExitShell {
				break
			}
			fmt.Fprintf(stderr, "  %s %s\n", ui.Fail.Sprint("[✗]"), ui.CodeSpan(err.Error()))
			code = 1
		}
	}
	return code
}

// promptFor splits what the user sees into two parts with different owners:
//
//   - contextLine: the session display (identity@relay), printed once with
//     fmt before each input line. Colors are fine here — nothing redraws it.
//   - inputPrompt: the string readline itself manages. readline strips ANSI
//     colors when measuring width (see runes.ColorFilter), so a single-line
//     colored prompt is safe; only embedded newlines break redraw (they
//     repeat the prompt once per typed character). Both parts use
//     ui.PromptFrame so ╭─ and ╰─ always begin in the same color.
//
// This is why the environment display and the input prompt are separate:
// the two-line look survives, but readline only ever owns the last line.
func promptFor(session *shellcmd.Session) (contextLine, inputPrompt string) {
	contextLine = "╭─[nextalk:-@-]"
	if session != nil {
		contextLine = session.Prompt()
	}
	return contextLine, ui.InputArrow()
}

// rlDebug appends one diagnostic line to the file named by NEXTALK_RL_DEBUG.
// It is unset in normal runs (zero overhead, zero output) and exists only to
// diagnose interactive prompt/redraw misbehavior on setups where the shell
// misbehaves: set it to a writable path, reproduce, then share the log.
func rlDebug(format string, args ...any) {
	path := os.Getenv("NEXTALK_RL_DEBUG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "rl: "+format+"\n", args...)
}

// runUnified is the primary interactive shell: one prompt, the whole
// command tree, session-aware prompt, in-memory history, completion.
func runUnified(api *core.Engine, cfg config.Config, session *shellcmd.Session, reg *shellcmd.Registry) {
	if !isTerminal(os.Stdin) {
		session.Interactive = false
		os.Exit(RunScript(reg, session, os.Stdin, os.Stdout, os.Stderr))
	}
	session.Interactive = true

	ui.Banner()
	fmt.Println()
	fmt.Println("  " + ui.Title.Sprint("Unified shell") + " — every operation lives here. " +
		ui.Code.Sprint("help") + " lists groups, " + ui.Code.Sprint("help <command>") + " shows usage, " +
		ui.Code.Sprint("quickstart") + " walks you through setup.")
	fmt.Println("  " + ui.Comment.Sprint("Tab completes everything · ↑/↓ recalls history (in-memory only, never saved) · `switch` enters a legacy shell."))
	fmt.Println()
	printWelcomeHints(session)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          ui.InputArrow(),
		AutoComplete:    newUnifiedCompleter(session, reg),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		// Route readline's screen output through the same writer as the
		// context line below (see ui.ConsoleOut): readline's built-in
		// Windows ANSI emulator mangles bold SGR combos (1;36 → white)
		// while the native terminal shows them correctly, which made
		// ╭─ sky blue and ╰─❯ white. One writer → one engine → same color.
		Stdout: ui.ConsoleOut,
		Stderr: ui.ConsoleOut,
	})
	if err != nil {
		printError("Failed to start input shell: %v", err)
		return
	}
	defer rl.Close()

	// needPrint gates the context line: it prints once per real command, and
	// never for empty input. Empty Readline() returns (bare Enter, or any
	// platform quirk that yields one) are swallowed silently so a misbehaving
	// console layer can never multiply the context line once per keystroke.
	needPrint := true
	for {
		if needPrint {
			needPrint = false
			// The context line is printed once per input (readline never
			// owns this line) through ui.ConsoleOut — the same writer
			// readline itself uses above — so both prompt lines share one
			// rendering engine and always begin in the same color.
			fmt.Fprintln(ui.ConsoleOut, session.PromptColored())
		}
		input, err := rl.Readline()
		rlDebug("returned %q err=%v", input, err)
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			fmt.Println(ui.Comment.Sprint("bye — history was in-memory only, nothing saved."))
			return
		}
		line := strings.TrimSpace(input)
		if line == "" {
			continue
		}
		// A real command was entered: reprint the context line before the
		// next prompt (visual separator, and picks up `use`/identity changes).
		needPrint = true
		session.History = append(session.History, line)
		words := session.ExpandAlias(strings.Fields(line))
		if len(words) > 0 && strings.ToLower(words[0]) == "switch" {
			if err := runSwitch(api, cfg, session, words[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "  %s %s\n", ui.Fail.Sprint("[✗]"), ui.CodeSpan(err.Error()))
			}
			continue
		}
		if err := execute(reg, session, line, os.Stdout, os.Stderr); err != nil {
			if err == errExitShell {
				fmt.Println(ui.Success.Sprint("  ✓ ") + ui.Info.Sprint("Goodbye! History was in-memory only."))
				return
			}
			fmt.Fprintf(os.Stderr, "  %s %s\n", ui.Fail.Sprint("[✗]"), ui.CodeSpan(err.Error()))
			printFriendlyHint(os.Stderr, err.Error())
		}
	}
}

// printWelcomeHints shows a 3-step getting-started card on shell launch.
// It adapts to what is already set so returning users see status, not noise.
func printWelcomeHints(session *shellcmd.Session) {
	if session == nil {
		return
	}
	fmt.Println("  " + session.StatusLine())
	fmt.Println()
	fmt.Println("   " + ui.Num.Sprint("1.") + " " + ui.CodeSpan("`identity init` → create who you are (or `identity load <id>`)"))
	fmt.Println("   " + ui.Num.Sprint("2.") + " " + ui.CodeSpan("`use relay <id>` → pick where messages travel (`transport list`)"))
	fmt.Println("   " + ui.Num.Sprint("3.") + " " + ui.CodeSpan("`peer connect <peer>` → handshake, then `message send <peer> hi`"))
	fmt.Println("  " + ui.Comment.Sprint("New here? run ") + ui.Code.Sprint("quickstart") +
		ui.Comment.Sprint(" for the full 5-step tour · lost? run ") + ui.Code.Sprint("help") + ui.Comment.Sprint("."))
	fmt.Println()
}

// printFriendlyHint adds one actionable follow-up line for the most common
// beginner errors (missing identity/relay, unknown command). Anything else
// stays quiet — no noise on top of the real error.
func printFriendlyHint(w io.Writer, msg string) {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "no identity"):
		fmt.Fprintln(w, "  "+ui.Comment.Sprint("→ fix: ")+ui.Code.Sprint("identity init")+ui.Comment.Sprint(" then ")+ui.Code.Sprint("use identity <id>"))
	case strings.Contains(m, "no transport") || strings.Contains(m, "no relay"):
		fmt.Fprintln(w, "  "+ui.Comment.Sprint("→ fix: ")+ui.Code.Sprint("transport list")+ui.Comment.Sprint(" then ")+ui.Code.Sprint("use relay <id>"))
	case strings.Contains(m, "unknown command"):
		fmt.Fprintln(w, "  "+ui.Comment.Sprint("→ try ")+ui.Code.Sprint("help")+ui.Comment.Sprint(" or ")+ui.Code.Sprint("quickstart"))
	}
}

// runSwitch implements `switch [name]`: no argument lists the legacy
// transport sub-shells, a name enters one directly. The session identity
// carries over — entering a legacy shell never drops who you are.
func runSwitch(api *core.Engine, cfg config.Config, session *shellcmd.Session, args []string) error {
	entries := registry.GUITransports()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, ui.Title.Sprint("Legacy transport sub-shells:"))
		for _, e := range entries {
			fmt.Fprintf(os.Stderr, "  %-10s %s\n", ui.Relay.Sprint(e.GUI.Name()), e.GUI.MenuLabel())
		}
		fmt.Fprintln(os.Stderr, "  "+ui.Comment.Sprint("Usage: ")+ui.Code.Sprint("switch <name>"))
		return nil
	}
	for _, e := range entries {
		if e.GUI.Name() == strings.ToLower(args[0]) {
			st := registry.NewState(api, cfg)
			if session.Identity != "" {
				if cl, err := Client.LoadClient(session.Identity); err == nil {
					st.ActiveClient = cl
					st.InitMailbox()
					st.InitFanout()
				}
			}
			if err := e.GUI.Init(st); err != nil {
				return fmt.Errorf("initialise transport: %w", err)
			}
			runSubShell(st, e.GUI)
			return nil
		}
	}
	return fmt.Errorf("unknown transport %q", args[0])
}
