// cmd/shell/shell.go
//
// Top-level interactive shell: the main transport menu plus the readline loop
// for whichever transport the user picks. All command handling lives in the
// transports themselves (cmd/worker, cmd/offline, …) — this file only drives
// input and delegates.
package shell

import (
	"fmt"
	"strings"

	"github.com/chzyer/readline"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

func clearScreen() { ui.ClearScreen() }

func printError(msg string, args ...any) { ui.Errorf(msg, args...) }

// RuntimeState is an alias for registry.State, NOT a separate struct.
// registry.GUITransport.Execute/Init are defined against *registry.State — if
// RuntimeState were its own distinct type (even with identical fields) it would
// not satisfy that interface, since Go interface satisfaction requires the
// declared type to match, not just its shape.
type RuntimeState = registry.State

func printMainMenu(entries []registry.Entry) {
	clearScreen()
	ui.Banner()
	fmt.Println()
	fmt.Println("  " + ui.Comment.Sprint("Pick a transport to enter its classic shell, or run") + " " +
		ui.Code.Sprint("nextalk shell") + " " + ui.Comment.Sprint("for the unified experience."))
	fmt.Println()

	for i, e := range entries {
		if e.GUI != nil {
			fmt.Printf("  %s %s\n", ui.Num.Sprintf("%2d.", i+1), ui.Info.Sprint(e.GUI.MenuLabel()))
		}
	}
	fmt.Printf("  %s %s\n\n", ui.Num.Sprintf("%2d.", len(entries)+1), ui.Fail.Sprint("Exit"))
	fmt.Println("  " + ui.Comment.Sprint("Tip: the unified shell does everything in one place —") + " " +
		ui.Code.Sprint("use identity") + ui.Comment.Sprint(" / ") + ui.Code.Sprint("use relay") + ui.Comment.Sprint(" once, then just chat."))
}

// RunGUI is the top-level interactive shell: the unified command tree
// (primary interface — every operation lives here) with the legacy
// per-transport menu one `switch` away. Piped stdin runs in scripting mode
// with exit codes instead of an interactive loop.
func RunGUI(api *core.Engine, cfg config.Config) {
	session := shellcmd.NewSession()
	runUnified(api, cfg, session, buildRegistry())
}

// readlineConfig builds the readline configuration for a transport sub-shell.
// Split out of runSubShell so tests can take the exact same config, attach pipes
// to Stdin/Stdout, and drive real Tab keypresses through the real readline event
// loop — the only way to verify the completer's offset/suffix contract
// end-to-end rather than by calling Do directly.
func readlineConfig(state *RuntimeState, t registry.GUITransport) *readline.Config {
	return &readline.Config{
		Prompt:       ui.InputArrow(),
		AutoComplete: newShellCompleter(state, t),
		// Same-writer rule as the unified shell (see ui.ConsoleOut):
		// readline's built-in Windows ANSI emulator mangles bold SGR
		// combos, so its screen output must go through the same engine
		// as our own prints, or ╭─ and ╰─❯ render in different colors.
		Stdout: ui.ConsoleOut,
		Stderr: ui.ConsoleOut,
		// HistoryFile is deliberately unset: shell input lines can contain
		// pasted handshake/ciphertext blobs, and persisting those to disk in
		// plaintext would leak protocol material into an unprotected file.
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}
}

// runSubShell drives the readline-backed loop for a single chosen transport.
// A fresh readline.Instance is built per transport so the prompt reflects the
// transport's name and the completer is bound to that transport's own command
// specs (see completer.go) rather than one shared hard-coded list.
func runSubShell(state *RuntimeState, t registry.GUITransport) {
	fmt.Fprintf(ui.ConsoleOut, "\n%s%s%s %s\n",
		ui.PromptFrame.Sprint("╭─["),
		ui.PromptFrame.Sprintf("nextalk:%s", t.Name()),
		ui.PromptFrame.Sprint("]"),
		ui.Comment.Sprint("— classic shell · `exit` goes back · `help` lists commands"))

	rl, err := readline.NewEx(readlineConfig(state, t))
	if err != nil {
		printError("Failed to start input shell: %v", err)
		return
	}
	defer rl.Close()

	for {
		input, err := rl.Readline()
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			return
		}
		if parts := strings.Fields(input); len(parts) > 0 {
			if !t.Execute(state, parts[0], parts[1:]) {
				return // back to main menu
			}
		}
	}
}
