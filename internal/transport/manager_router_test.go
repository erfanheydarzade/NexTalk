package transport

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Config must be empty or a valid JSON object with double quotes.
// Single-quoted or unquoted Go-map syntax previously failed silently in the
// bridge (invalid JSON ignored -> "no router_url" on peer connect).
func TestSetConfigValidatesJSON(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", goodManifest, "fake-bin", []byte("dummy"))
	ctx := context.Background()
	if _, err := m.Install(ctx, pkg, false); err != nil {
		t.Fatal(err)
	}

	valid := `{"router_url":"https://gw.neroxen.ir"}`
	if err := m.SetConfig("fake", valid); err != nil {
		t.Fatalf("valid config must store: %v", err)
	}
	// Empty clears.
	if err := m.SetConfig("fake", ""); err != nil {
		t.Fatalf("empty config must clear: %v", err)
	}

	bad := []string{
		`{router_url:https://gw.neroxen.ir}`,
		`{'router_url':'https://gw.neroxen.ir'}`,
		`{"router_url":'https://gw.neroxen.ir'}`,
		`not json at all`,
		`["array"]`,
		`"string"`,
	}
	for _, b := range bad {
		if err := m.SetConfig("fake", b); err == nil {
			t.Fatalf("invalid config must fail: %q", b)
		}
	}
}

// Attachments must survive a manager restart (state.json persistence) so two
// identities on one machine keep their mailboxes.
func TestAttachmentsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", goodManifest, "fake-bin", []byte("dummy"))
	ctx := context.Background()
	if _, err := m.Install(ctx, pkg, false); err != nil {
		t.Fatal(err)
	}
	a1 := Attachment{MailboxID: strings.Repeat("a", 32), ReadSecret: strings.Repeat("b", 64), ShardURL: "https://shard", RouterURL: "https://router"}
	a2 := Attachment{MailboxID: strings.Repeat("c", 32), ReadSecret: strings.Repeat("d", 64), ShardURL: "https://shard", RouterURL: "https://router"}
	if err := m.AddAttachment("fake", a1); err != nil {
		t.Fatal(err)
	}
	if err := m.AddAttachment("fake", a2); err != nil {
		t.Fatal(err)
	}
	// Simulate restart: new manager over the same dir.
	m2, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := m2.Attachments("fake")
	if len(got) != 2 {
		t.Fatalf("want 2 attachments after restart, got %d", len(got))
	}
}

// Start must replay stored attachments into a fresh bridge process. Without
// this, every shell command spawns a new bridge with empty in-memory state
// and peer connect fails with "no router_url" despite valid state.json.
func TestStartReplaysAttachments(t *testing.T) {
	if os.Getenv("NTX_FAKE_TRANSPORT") == "1" {
		t.Skip("helper")
	}
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	entry := "fake-bin"
	manifest := goodManifest
	if runtime.GOOS == "windows" {
		entry = "fake-bin.exe"
		manifest = fmt.Sprintf(`{"id":"fake","name":"Fake","version":"0.0.1","api_version":"1","entry":%q,"capabilities":["message"],"permissions":[]}`, entry)
	}
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", manifest, entry, raw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := m.Install(ctx, pkg, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("NTX_FAKE_TRANSPORT", "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("NTX_FAKE_TRANSPORT")

	// Two mailboxes (two identities sharing one machine).
	if err := m.AddAttachment("fake", Attachment{
		MailboxID: strings.Repeat("1", 32), ReadSecret: strings.Repeat("2", 64),
		ShardURL: "https://shard", RouterURL: "https://router",
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddAttachment("fake", Attachment{
		MailboxID: strings.Repeat("3", 32), ReadSecret: strings.Repeat("4", 64),
		ShardURL: "https://shard", RouterURL: "https://router",
	}); err != nil {
		t.Fatal(err)
	}

	tr, err := m.Start(ctx, "fake")
	if err != nil {
		t.Fatalf("Start with attachments must replay attach: %v", err)
	}
	// Transport is usable immediately after Start (peer connect path).
	frame := append([]byte{0x03}, []byte("hello")...)
	if err := tr.SendFrame(ctx, frame, RouteHint{RecipientPub: make([]byte, 32)}); err != nil {
		t.Fatalf("send after replay: %v", err)
	}
	_ = m.Stop(ctx, "fake")

	// Restart (fresh manager + fresh bridge) must replay again.
	m2, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := m2.Start(ctx, "fake")
	if err != nil {
		t.Fatalf("restart must replay attachments: %v", err)
	}
	if err := tr2.SendFrame(ctx, frame, RouteHint{RecipientPub: make([]byte, 32)}); err != nil {
		t.Fatalf("send after restart: %v", err)
	}
	_ = m2.Stop(ctx, "fake")
}

// Corrupt attachment state must fail fast with a clear error, not a silent
// router misroute later.
func TestStartRejectsCorruptAttachment(t *testing.T) {
	if os.Getenv("NTX_FAKE_TRANSPORT") == "1" {
		t.Skip("helper")
	}
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	raw, _ := os.ReadFile(self)
	entry := "fake-bin"
	manifest := goodManifest
	if runtime.GOOS == "windows" {
		entry = "fake-bin.exe"
		manifest = fmt.Sprintf(`{"id":"fake","name":"Fake","version":"0.0.1","api_version":"1","entry":%q,"capabilities":["message"],"permissions":[]}`, entry)
	}
	pkg := writeNTX(t, t.TempDir(), "fake.ntx", manifest, entry, raw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := m.Install(ctx, pkg, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("NTX_FAKE_TRANSPORT", "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("NTX_FAKE_TRANSPORT")

	// Bypass validation by writing state directly.
	m.state.Attach["fake"] = []Attachment{{MailboxID: "zz", ReadSecret: strings.Repeat("2", 64), ShardURL: "s"}}
	if _, err := m.Start(ctx, "fake"); err == nil {
		t.Fatal("corrupt attachment must fail Start")
	}
}
