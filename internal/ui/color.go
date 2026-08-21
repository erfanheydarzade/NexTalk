// Package ui provides shared terminal-color helpers built on
// github.com/fatih/color. Colors are automatically disabled when stdout is
// piped to a file or a terminal that does not support ANSI escape codes —
// fatih/color checks isatty internally on every write.
package ui

import (
	"fmt"

	"github.com/fatih/color"
)

// Reusable color instances. Declare once here; import and use everywhere.
// Creating a *color.Color per call site is unnecessary and noisy.
var (
	// Success is green — used for [✓] confirmations.
	Success = color.New(color.FgGreen)
	// Fail is red — used for [✗] errors.
	Fail = color.New(color.FgRed)
	// Warning is yellow — used for [!] warnings and unread counts.
	Warning = color.New(color.FgYellow)
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
)

// ClearScreen clears the terminal via ANSI cursor/erase sequences.
// This is a terminal control sequence, not a colour code, so it is kept here
// rather than being replaced with a fatih/color primitive.
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// Successf prints "  [✓] <msg>\n" with a green [✓] indicator.
func Successf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Success.Sprint("[✓]"), fmt.Sprintf(format, args...))
}

// Errorf prints "  [✗] <msg>\n" with a red [✗] indicator.
func Errorf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Fail.Sprint("[✗]"), fmt.Sprintf(format, args...))
}

// Warnf prints "  [!] <msg>\n" with a yellow [!] indicator.
func Warnf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Warning.Sprint("[!]"), fmt.Sprintf(format, args...))
}

// Infof prints "  [i] <msg>\n" with a cyan [i] indicator.
func Infof(format string, args ...any) {
	fmt.Printf("  %s %s\n", Info.Sprint("[i]"), fmt.Sprintf(format, args...))
}

// Mailf prints "  [✉] <msg>\n" with a magenta [✉] indicator.
func Mailf(format string, args ...any) {
	fmt.Printf("  %s %s\n", Mail.Sprint("[✉]"), fmt.Sprintf(format, args...))
}
