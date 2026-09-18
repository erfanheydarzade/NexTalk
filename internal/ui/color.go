// Package ui provides shared terminal-color helpers built on
// github.com/fatih/color. Colors are automatically disabled when stdout is
// not a TTY or NO_COLOR/TERM=dumb is set — fatih/color checks this
// internally, so Sprint/Fprintf calls below are plain text in tests and
// piped scripts, and colorful in the interactive shell.
package ui

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Reusable color instances. Declare once here; import and use everywhere.
// Creating a *color.Color per call site is unnecessary and noisy.
var (
	// Success is green — used for [✓] confirmations.
	Success = color.New(color.FgGreen)
	// SuccessBold is bright bold green — headline confirmations.
	SuccessBold = color.New(color.Bold, color.FgHiGreen)
	// Fail is red — used for [✗] errors.
	Fail = color.New(color.FgRed)
	// FailBold is bold red — fatal errors.
	FailBold = color.New(color.Bold, color.FgHiRed)
	// Warning is yellow — used for [!] warnings and unread counts.
	Warning = color.New(color.FgYellow)
	// WarningBold is bold yellow — prominent warnings.
	WarningBold = color.New(color.Bold, color.FgHiYellow)
	// Info is cyan — used for [i] informational messages and peer IDs.
	Info = color.New(color.FgCyan)
	// Mail is magenta — used for [✉] incoming message notifications.
	Mail = color.New(color.FgMagenta)
	// Bold is bold-weight with no color change.
	Bold = color.New(color.Bold)
	// Header is bold blue — used for mode banners (❖ … ❖).
	Header = color.New(color.Bold, color.FgBlue)
	// BoldCyan is bold cyan — used for the NexTalk CLI frame.
	BoldCyan = color.New(color.Bold, color.FgCyan)
	// Comment is dim gray — used for previews, timestamps, and footnotes.
	Comment = color.New(color.FgHiBlack)
	// Code highlights `backticked` spans, file names and command names.
	Code = color.New(color.Bold, color.FgHiCyan)
	// Dim is a faint white for secondary text.
	Dim = color.New(color.FgHiBlack)
	// Identity highlights the active identity in prompts and status.
	Identity = color.New(color.Bold, color.FgHiGreen)
	// Relay highlights the active relay/transport name.
	Relay = color.New(color.Bold, color.FgHiMagenta)
	// Peer highlights peer IDs and mailbox addresses.
	Peer = color.New(color.FgHiYellow)
	// Num highlights menu numbers and counts.
	Num = color.New(color.Bold, color.FgHiYellow)
	// Title highlights section titles in help and status screens.
	Title = color.New(color.Bold, color.FgHiWhite)
	// PromptFrame is the single frame color for the whole shell prompt.
	// Both lines — ╭─[context] and ╰─❯ input — use this, so the two
	// beginnings always match. chzyer/readline strips ANSI via ColorFilter
	// when measuring width, so a single-line colored prompt is safe;
	// only embedded newlines break redraw (hence the split design).
	PromptFrame = color.New(color.Bold, color.FgCyan)
	// PromptArrow is the input arrow color (alias of PromptFrame).
	PromptArrow = PromptFrame
)

// ConsoleOut is the writer interactive shell output must go through so the
// prompt renders identically on every platform. On Windows this is
// go-colorable's VT-capable stdout; elsewhere it is os.Stdout.
//
// Why this exists: the context line (╭─[…]) is printed with fmt while the
// input arrow (╰─❯) is rendered by chzyer/readline, whose built-in Windows
// ANSI emulator mangles combined SGR codes — it turns bold-cyan (1;36)
// into plain white, while the native terminal shows sky blue. Routing
// readline's Stdout/Stderr AND our own prompt prints through this one
// writer puts both lines through the same engine, so they always match.
var ConsoleOut = color.Output

// PrintLine prints one line to ConsoleOut (see ConsoleOut).
func PrintLine(a ...any) {
	fmt.Fprintln(ConsoleOut, a...)
}

// ClearScreen clears the terminal via ANSI cursor/erase sequences.
// This is a terminal control sequence, not a colour code, so it is kept here
// rather than being replaced with a fatih/color primitive.
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// BannerLines returns the NexTalk CLI frame lines, colorized.
func BannerLines() []string {
	return []string{
		BoldCyan.Sprint("╔═══════════════════════════════════════╗"),
		BoldCyan.Sprint("║  ") + Title.Sprint("🔐 NexTalk — secure messaging shell") + BoldCyan.Sprint("  ║"),
		BoldCyan.Sprint("╚═══════════════════════════════════════╝"),
	}
}

// Banner prints the NexTalk CLI frame.
func Banner() {
	for _, l := range BannerLines() {
		fmt.Println(l)
	}
}

// PromptContext renders the session display with colors:
// ╭─[nextalk:alice@green @ relay@magenta]. Missing pieces render dimmed.
// The frame (╭─[ : @ ]) always uses PromptFrame — the same color as the
// ╰─❯ input arrow — so both prompt lines begin in the same color.
func PromptContext(identity, relay string) string {
	id := identity
	rl := relay
	if id == "" || id == "-" {
		id = Dim.Sprint("-")
	} else {
		id = Identity.Sprint(shorten(id))
	}
	if rl == "" || rl == "-" {
		rl = Dim.Sprint("-")
	} else {
		rl = Relay.Sprint(rl)
	}
	return PromptFrame.Sprint("╭─[") + PromptFrame.Sprint("nextalk") +
		PromptFrame.Sprint(":") + id + PromptFrame.Sprint("@") + rl + PromptFrame.Sprint("]")
}

// InputArrow returns the colorized input prompt arrow. Single-line ANSI is
// readline-safe (it filters colors when measuring width); only newlines
// break redraw, so this must never contain "\n".
func InputArrow() string {
	return PromptFrame.Sprint("╰─❯ ")
}

func shorten(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

// CodeSpan highlights `backticked` spans in msg with the Code color.
// Unbalanced backticks are left as-is. Plain when colors are disabled.
func CodeSpan(msg string) string {
	if !strings.Contains(msg, "`") {
		return msg
	}
	var sb strings.Builder
	open := false
	cur := strings.Builder{}
	for _, r := range msg {
		if r == '`' {
			if open {
				sb.WriteString(Code.Sprint(cur.String()))
				cur.Reset()
				open = false
			} else {
				open = true
			}
			continue
		}
		if open {
			cur.WriteRune(r)
		} else {
			sb.WriteRune(r)
		}
	}
	if open {
		// Unbalanced: restore the opening backtick literally.
		sb.WriteString("`")
		sb.WriteString(cur.String())
	}
	return sb.String()
}

// Successf prints "  [✓] <msg>\n" with a green [✓] indicator.
func Successf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Success.Sprint("[✓]"), CodeSpan(fmt.Sprintf(format, args...)))
}

// Errorf prints "  [✗] <msg>\n" with a red [✗] indicator.
func Errorf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Fail.Sprint("[✗]"), CodeSpan(fmt.Sprintf(format, args...)))
}

// Warnf prints "  [!] <msg>\n" with a yellow [!] indicator.
func Warnf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Warning.Sprint("[!]"), CodeSpan(fmt.Sprintf(format, args...)))
}

// Infof prints "  [i] <msg>\n" with a cyan [i] indicator.
func Infof(format string, args ...any) {
	fmt.Printf("  %s %s\n", Info.Sprint("[i]"), CodeSpan(fmt.Sprintf(format, args...)))
}

// Mailf prints "  [✉] <msg>\n" with a magenta [✉] indicator.
func Mailf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Mail.Sprint("[✉]"), CodeSpan(fmt.Sprintf(format, args...)))
}
