// cmd/shell/shell.go
//
// Top-level interactive shell: the main transport menu plus the readline loop
// for whichever transport the user picks. All command handling lives in the
// transports themselves (cmd/worker, cmd/offline, …) — this file only drives
// input and delegates.
package shell

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
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
	ui.BoldCyan.Println("╔════════════════════════════════════════╗")
	ui.BoldCyan.Println("║               NexTalk CLI              ║")
	ui.BoldCyan.Println("╚════════════════════════════════════════╝")
	fmt.Println()

	for i, e := range entries {
		if e.GUI != nil {
			fmt.Printf("  %d. %s\n", i+1, e.GUI.MenuLabel())
		}
	}
	fmt.Printf("  %d. Exit\n\n", len(entries)+1)
}

// RunGUI is the top-level interactive shell. It reads all GUITransports from
// the registry — it never names a specific transport.
func RunGUI(api *core.Engine, cfg config.Config) {
	scanner := bufio.NewScanner(os.Stdin)
	state := registry.NewState(api, cfg)
	entries := registry.GUITransports()
	exitChoice := fmt.Sprintf("%d", len(entries)+1)

	for {
		printMainMenu(entries)
		ui.Bold.Print("Select ❯ ")

		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())

		if choice == exitChoice || choice == "exit" || choice == "q" {
			ui.Infof("Goodbye!")
			return
		}

		idx := -1
		for i := range entries {
			if choice == fmt.Sprintf("%d", i+1) {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}

		t := entries[idx].GUI
		if err := t.Init(state); err != nil {
			printError("Failed to initialise transport: %v", err)
			continue
		}

		runSubShell(state, t)
	}
}

// readlineConfig builds the readline configuration for a transport sub-shell.
// Split out of runSubShell so tests can take the exact same config, attach pipes
// to Stdin/Stdout, and drive real Tab keypresses through the real readline event
// loop — the only way to verify the completer's offset/suffix contract
// end-to-end rather than by calling Do directly.
func readlineConfig(state *RuntimeState, t registry.GUITransport) *readline.Config {
	return &readline.Config{
		Prompt:       ui.Success.Sprint("╰─❯ "),
		AutoComplete: newShellCompleter(state, t),
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
	fmt.Printf("\n%s%s%s\n",
		ui.Info.Sprint("╭─["),
		ui.Success.Sprintf("nextalk:%s", t.Name()),
		ui.Info.Sprint("]"))

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
