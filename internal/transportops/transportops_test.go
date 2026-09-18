package transportops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/erfanheydarzade/NexTalk/internal/filetransfer"
	"github.com/erfanheydarzade/NexTalk/internal/shellcmd"
)

func testDeps(t *testing.T) (*Deps, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	return &Deps{
		TransportsDir: t.TempDir(),
		Stdout:        &stdout,
		Stderr:        &stderr,
		Session:       shellcmd.NewSession(),
	}, &stdout, &stderr
}

func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestListEmpty(t *testing.T) {
	d, stdout, _ := testDeps(t)
	list, err := List(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("want empty: %v", list)
	}
	if stdout.Len() != 0 {
		t.Fatalf("machine-quiet human output leaked to stdout: %q", stdout.String())
	}
}

func TestListJSON(t *testing.T) {
	d, stdout, _ := testDeps(t)
	d.JSON = true
	if _, err := List(d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"transports"`) {
		t.Fatalf("json missing: %q", stdout.String())
	}
}

func TestAttachValidation(t *testing.T) {
	d, _, _ := testDeps(t)
	// Bad hex fails before anything touches disk or network.
	if err := Attach(d, AttachParams{TransportID: "x", MailboxID: "zz", ReadSecret: "aa", ShardURL: "s"}); err == nil {
		t.Fatal("bad mailbox must fail")
	}
	// Well-formed but nothing installed.
	if err := Attach(d, AttachParams{
		TransportID: "ghost", MailboxID: strings.Repeat("a", 32),
		ReadSecret: strings.Repeat("b", 64), ShardURL: "s",
	}); err == nil {
		t.Fatal("unknown transport must fail")
	}
}

func TestSecretOrConfirm(t *testing.T) {
	d, _, _ := testDeps(t)
	if _, err := d.SecretOr("", "prompt: "); err == nil {
		t.Fatal("unwired secret must fail")
	}
	if v, err := d.SecretOr("given", "prompt: "); err != nil || v != "given" {
		t.Fatalf("flag wins: %v %v", v, err)
	}
	if ok, err := d.ConfirmOr("x?"); err != nil || !ok {
		t.Fatalf("unwired confirm auto-yes: %v %v", ok, err)
	}
	d.Confirm = func(string) (bool, error) { return false, nil }
	if ok, err := d.ConfirmOr("x?"); err != nil || ok {
		t.Fatal("explicit no must hold")
	}
}

func testManifestBytes(t *testing.T) []byte {
	t.Helper()
	mf := &filetransfer.Manifest{
		FileName: "demo.bin", PlainSize: 12, CipherSize: 60,
		ChunkSize: 32, ChunkCount: 2,
		FileHash:   bytes.Repeat([]byte{0xA}, 32),
		CipherHash: bytes.Repeat([]byte{0xB}, 32),
	}
	return mf.Bytes()
}

func TestXferInspectOffline(t *testing.T) {
	d, stdout, stderr := testDeps(t)
	raw, err := filetransfer.MarshalTicket(&filetransfer.Ticket{
		Transfer: bytes.Repeat([]byte{1}, 16),
		Secret:   bytes.Repeat([]byte{2}, 32),
		Shard:    "https://shard",
		Manifest: testManifestBytes(t),
		From:     "peer1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := XferInspect(d, filetransfer.EncodeTicketString(raw)); err != nil {
		t.Fatal(err)
	}
	out := stderr.String()
	if !strings.Contains(out, "https://shard") || strings.Contains(out, "02020202") {
		t.Fatalf("inspect must show shard, never raw secret: %q", out)
	}
	if stdout.Len() != 0 {
		t.Fatalf("human leaked to stdout: %q", stdout.String())
	}
	// Garbage rejected without network.
	if err := XferInspect(d, "!!!"); err == nil {
		t.Fatal("garbage ticket must fail")
	}
}

func TestXferInspectShowSecrets(t *testing.T) {
	d, _, stderr := testDeps(t)
	d.ShowSecrets = true
	secret := bytes.Repeat([]byte{2}, 32)
	raw, err := filetransfer.MarshalTicket(&filetransfer.Ticket{
		Transfer: secret[:16], Secret: secret, Shard: "s", Manifest: testManifestBytes(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := XferInspect(d, filetransfer.EncodeTicketString(raw)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "0202") {
		t.Fatalf("show-secrets must reveal: %q", stderr.String())
	}
}

func TestIdentityInitSelects(t *testing.T) {
	chdirTemp(t)
	d, _, stderr := testDeps(t)
	if err := IdentityInit(d); err != nil {
		t.Fatal(err)
	}
	if d.Session.Identity == "" {
		t.Fatal("init must select identity")
	}
	if !strings.Contains(stderr.String(), "✓") {
		t.Fatalf("human confirmation missing: %q", stderr.String())
	}
	// Second call lists the created profile.
	d2, _, _ := testDeps(t)
	d2.Session = d.Session
	if err := IdentityList(d2); err != nil {
		t.Fatal(err)
	}
}

func TestContactMailboxRoundTrip(t *testing.T) {
	chdirTemp(t)
	d, _, _ := testDeps(t)
	if err := ContactAdd(d, "alice", "peer-id-alice"); err != nil {
		t.Fatal(err)
	}
	if err := ContactNote(d, "alice", "met 2025"); err != nil {
		t.Fatal(err)
	}
	if err := ContactInfo(d, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := ContactList(d); err != nil {
		t.Fatal(err)
	}
	if err := ContactRename(d, "alice", "ali"); err != nil {
		t.Fatal(err)
	}
	if err := ContactRemove(d, "ali"); err != nil {
		t.Fatal(err)
	}
	if err := ContactRemove(d, "ali"); err == nil {
		t.Fatal("double remove must fail")
	}
}

func TestMailboxEmpty(t *testing.T) {
	chdirTemp(t)
	d, _, stderr := testDeps(t)
	if err := IdentityInit(d); err != nil {
		t.Fatal(err)
	}
	if err := MailboxList(d, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "empty") {
		t.Fatalf("empty hint: %q", stderr.String())
	}
	if err := MailboxRead(d, "", "nobody"); err == nil {
		t.Fatal("unknown thread must fail")
	}
}

func TestOpsNeedIdentity(t *testing.T) {
	d, _, _ := testDeps(t)
	d.Session.Identity = ""
	if err := XferSend(d, XferSendParams{TransportID: "t", Peer: "p", File: "f"}); err == nil {
		t.Fatal("send without identity must fail fast")
	}
	if err := XferRecv(d, XferRecvParams{TransportID: "t", Identity: "", Peer: "p", TicketB64: "eA==", Out: "o"}); err == nil {
		t.Fatal("recv without identity must fail fast")
	}
	if err := MessageSend(d, MessageSendParams{Peer: "p", Text: "hi"}); err == nil {
		t.Fatal("message without relay must fail fast")
	}
}

func TestRelayListEmpty(t *testing.T) {
	d, _, stderr := testDeps(t)
	relays, err := RelayList(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 0 {
		t.Fatalf("want none: %v", relays)
	}
	if !strings.Contains(stderr.String(), "No message relays") {
		t.Fatalf("hint: %q", stderr.String())
	}
}

func TestTransferRefRecord(t *testing.T) {
	d, _, _ := testDeps(t)
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No transport installed: must fail, but must not record anything.
	if err := XferSend(d, XferSendParams{TransportID: "ghost", Identity: "nobody", Peer: "p", File: path}); err == nil {
		t.Fatal("ghost transport must fail")
	}
	if len(d.Session.Transfers) != 0 {
		t.Fatal("failed send must not record")
	}
}
