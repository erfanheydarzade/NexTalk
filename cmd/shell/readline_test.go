package shell

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chzyer/readline"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

// TestReadlineTab drives the real readline event loop with real Tab keypresses
// instead of calling shellCompleter.Do directly.
//
// This is what actually proves the user-facing behaviour from the bug report —
// "one Tab should complete the ID" — because it exercises the parts a direct Do()
// call cannot: readline's candidate aggregation, the offset arithmetic that
// splices a suffix into the line buffer, and the final submitted line.
func TestReadlineTab(t *testing.T) {
	cases := []struct {
		name  string
		peers []string
		keys  string
		want  string
	}{{
		name:  "unique peer prefix expands to the full ID",
		peers: []string{"t1dABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghij"},
		keys:  "connect t1d\t\r",
		want:  "connect t1dABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghij",
	}, {
		name: "command name completes",
		keys: "conn\t\r",
		want: "connect",
	}, {
		// Expanding to one of two matches is the failure mode that would send a
		// message to the wrong peer, so Tab must stop at the shared prefix.
		name:  "ambiguous peers stop at the shared prefix",
		peers: []string{"sharedPrefixAAAA1111", "sharedPrefixBBBB2222"},
		keys:  "connect shared\t\r",
		want:  "connect sharedPrefix",
	}, {
		// The common case right after a handshake: Tab on an empty slot.
		name:  "empty argument slot fills in the only peer",
		peers: []string{"onlyPeer9999888877776666"},
		keys:  "mailbox \t\r",
		want:  "mailbox onlyPeer9999888877776666",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)

			state := &registry.State{}
			for _, p := range tc.peers {
				state.RememberPeer(p)
			}

			if got := strings.TrimSpace(runReadline(t, state, tc.keys)); got != tc.want {
				t.Fatalf("submitted line = %q, want %q", got, tc.want)
			}
		})
	}
}

// runReadline feeds keys through a real readline.Instance built from the shell's
// own config, and returns the line Readline() produced.
//
// Interactive mode is forced with no-op raw-mode hooks: pipes aren't TTYs, so
// otherwise readline takes its non-interactive path and never calls the completer.
func runReadline(t *testing.T, state *registry.State, keys string) string {
	t.Helper()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()

	cfg := readlineConfig(state, &fakeTransport{})
	cfg.Stdin = pr
	cfg.Stdout = io.Discard
	cfg.Stderr = io.Discard
	cfg.ForceUseInteractive = true
	cfg.FuncIsTerminal = func() bool { return true }
	cfg.FuncMakeRaw = func() error { return nil }
	cfg.FuncExitRaw = func() error { return nil }
	cfg.FuncGetWidth = func() int { return 120 }
	cfg.FuncOnWidthChanged = func(func()) {}

	rl, err := readline.NewEx(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	go func() {
		defer pw.Close()
		// One rune at a time: readline distinguishes a first Tab (complete /
		// aggregate) from a second consecutive Tab (select mode), and a bulk
		// write can coalesce them.
		for _, r := range keys {
			if _, err := pw.WriteString(string(r)); err != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := rl.Readline()
		done <- result{line, err}
	}()

	select {
	case res := <-done:
		if res.err != nil && !errors.Is(res.err, io.EOF) {
			t.Fatalf("Readline: %v", res.err)
		}
		return res.line
	case <-time.After(10 * time.Second):
		t.Fatal("Readline timed out — the completer likely blocked or never returned")
		return ""
	}
}
