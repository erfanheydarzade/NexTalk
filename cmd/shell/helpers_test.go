package shell

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
)

// testConfig is an empty transport config. The offline transport needs no
// WORKER_URL/PROXY_URL, so a zero value keeps tests off the network entirely.
func testConfig() config.Config { return config.Config{} }

// tempDirs returns n isolated directories and restores the CWD on cleanup.
// Identities are files in the CWD (client.SaveClient uses a bare relative path),
// so one directory per simulated machine.
//
// The chdir-restore cleanup is registered AFTER t.TempDir's own: cleanups run
// LIFO, so the CWD is restored before TempDir tries to delete the directories.
// Windows refuses to remove a directory that is a process's CWD.
func tempDirs(t *testing.T, n int) []string {
	t.Helper()

	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	dirs := make([]string, n)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	t.Cleanup(func() { _ = os.Chdir(root) })
	return dirs
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
}

// exec runs one sub-shell command and returns what it printed. Transports report
// results with fmt.Printf rather than returning them, so capturing stdout is the
// only way to get at an offer/answer blob.
func exec(t *testing.T, tr registry.GUITransport, st *registry.State, cmd string, args ...string) string {
	t.Helper()
	return captureStdout(t, func() {
		if !tr.Execute(st, cmd, args) {
			t.Fatalf("%s returned false (transport wants to exit)", cmd)
		}
	})
}

// execWithStdin is exec for commands that read pasted JSON from stdin
// (offline's accept/finish). It swaps in a pipe carrying input, re-runs Init so
// the transport's cached scanner reads that pipe, then runs cmd.
func execWithStdin(t *testing.T, tr registry.GUITransport, st *registry.State, input, cmd string, args ...string) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r

	// Write from a goroutine: a handshake offer is ~9 KB, over the pipe buffer,
	// so an inline write would deadlock instead of failing.
	writeErr := make(chan error, 1)
	go func() {
		_, err := w.WriteString(input)
		_ = w.Close()
		writeErr <- err
	}()

	defer func() {
		os.Stdin = orig
		_ = r.Close()
		if err := <-writeErr; err != nil {
			t.Errorf("write to stdin pipe: %v", err)
		}
	}()

	// PITFALL: OfflineGUITransport.Init caches a bufio.Scanner over os.Stdin, so
	// a scanner built before this swap would block on the real stdin forever.
	if err := tr.Init(st); err != nil {
		t.Fatal(err)
	}
	return exec(t, tr, st, cmd, args...)
}

// capture redirects os.Stdout for the duration of fn and returns what was
// written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()

	func() {
		defer func() {
			os.Stdout = orig
			_ = w.Close()
		}()
		fn()
	}()

	out := <-done
	_ = r.Close()
	return out
}

// extractJSON pulls the first complete JSON object out of a transport's
// human-formatted output, which prefixes the blob with a status line.
func extractJSON(t *testing.T, out string) string {
	t.Helper()

	start := strings.IndexByte(out, '{')
	if start < 0 {
		t.Fatalf("no JSON object in output: %q", out)
	}

	var depth int
	var inString, escaped bool
	for i := start; i < len(out); i++ {
		switch c := out[i]; {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case inString: // braces inside strings don't nest
		case c == '{':
			depth++
		case c == '}':
			if depth--; depth == 0 {
				blob := out[start : i+1]
				if !json.Valid([]byte(blob)) {
					t.Fatalf("extracted invalid JSON: %q", blob)
				}
				return blob
			}
		}
	}
	t.Fatalf("unterminated JSON object in output: %q", out)
	return ""
}
