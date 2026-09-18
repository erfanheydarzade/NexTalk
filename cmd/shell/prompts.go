package shell

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// errExitShell unwinds the unified loop. It is a sentinel, never user output.
var errExitShell = errors.New("exit shell")

// promptSecret implements hidden input for shell SecretOr calls. It tries
// readline.Password (no echo) and falls back to a plain stdin read so a
// missing TTY degrades instead of hanging.
func promptSecret(prompt string) (string, error) {
	if pass, err := readline.Password(prompt); err == nil {
		return string(pass), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptConfirm implements yes/no confirmation for shell ConfirmOr calls.
// Empty answer means no — destructive commands stay safe by default.
func promptConfirm(prompt string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s %s ", ui.Warning.Sprint("?"), ui.CodeSpan(prompt)+ui.Comment.Sprint(" [y/N]"))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
