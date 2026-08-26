package mailbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdirTemp isolates file-backed stores from the repo working directory.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	// Registered after TempDir's own cleanup so it runs first (LIFO): Windows
	// refuses to delete a directory that is a process's CWD.
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func TestPersistAndReload(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIncoming("bob", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendOutgoing("bob", "hi back"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIncoming("carol", "wrong window"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	thread, ok := reloaded.Get("bob")
	if !ok {
		t.Fatal("thread for bob lost after reload")
	}
	if len(thread.Messages) != 2 {
		t.Fatalf("expected 2 messages for bob, got %d", len(thread.Messages))
	}
	if thread.Messages[0].Direction != Incoming || thread.Messages[0].Body != "hello" {
		t.Errorf("unexpected first message: %+v", thread.Messages[0])
	}
	if thread.Messages[0].IsRead {
		t.Error("incoming messages must start unread")
	}
	if !thread.Messages[1].IsRead {
		t.Error("outgoing messages must start read")
	}

	if got := reloaded.UnreadTotal(); got != 2 { // bob's "hello" + carol's msg
		t.Errorf("UnreadTotal = %d, want 2", got)
	}
}

func TestReadMarksThreadReadAndPersists(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"a", "b", "c"} {
		if err := st.AppendIncoming("bob", body); err != nil {
			t.Fatal(err)
		}
	}

	msgs, err := st.Read("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	// Returned copy reflects pre-read state; store must now be clean.
	if got := st.UnreadTotal(); got != 0 {
		t.Fatalf("UnreadTotal after Read = %d, want 0", got)
	}

	reloaded, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.UnreadTotal(); got != 0 {
		t.Errorf("read state not persisted: UnreadTotal = %d", got)
	}
}

func TestReadUnknownThread(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Read("nobody"); err == nil {
		t.Fatal("expected error reading unknown thread")
	}
}

func TestResolveThreadForms(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	const ctxID = "abc123def456"
	if err := st.AppendGroupIncoming(ctxID, "Friends", "bob", "hey all"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendGroupOutgoing(ctxID, "Friends", "hi friends"); err != nil {
		t.Fatal(err)
	}

	want := GroupKey(ctxID)

	// Full context ID.
	if key, err := st.ResolveThread(ctxID); err != nil || key != want {
		t.Errorf("by full ID: key=%q err=%v", key, err)
	}
	// Prefixed forms.
	for _, arg := range []string{"ctx:" + ctxID, "group:" + ctxID} {
		if key, err := st.ResolveThread(arg); err != nil || key != want {
			t.Errorf("by %q: key=%q err=%v", arg, key, err)
		}
	}
	// Unique prefix of the ID — the form notifications suggest.
	if key, err := st.ResolveThread(ctxID[:8]); err != nil || key != want {
		t.Errorf("by ID prefix: key=%q err=%v", key, err)
	}
	if key, err := st.ResolveThread("group:" + ctxID[:6]); err != nil || key != want {
		t.Errorf("by prefixed ID prefix: key=%q err=%v", key, err)
	}
	// Exact display name, case-insensitive.
	if key, err := st.ResolveThread("Friends"); err != nil || key != want {
		t.Errorf("by name: key=%q err=%v", key, err)
	}
	if _, err := st.ResolveThread("FRIENDS"); err != nil {
		t.Errorf("case-insensitive lookup failed: %v", err)
	}
	// Unknown name fails.
	if _, err := st.ResolveThread("Enemies"); err == nil {
		t.Error("expected miss for unknown group")
	}
}

func TestResolveThreadAmbiguity(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	// Two contexts sharing an 8-char prefix; names unique per context.
	const shared = "deadbeef"
	if err := st.AppendGroupIncoming(shared+"0000", "Alpha", "bob", "a"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendGroupIncoming(shared+"1111", "Beta", "carol", "b"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.ResolveThread(shared); err == nil {
		t.Error("ambiguous ID prefix must fail")
	} else if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("unexpected error: %v", err)
	}

	// Exact IDs still resolve.
	if key, err := st.ResolveThread(shared + "0000"); err != nil || key != GroupKey(shared+"0000") {
		t.Errorf("exact ID after ambiguity: key=%q err=%v", key, err)
	}
	// Distinct names resolve.
	if key, err := st.ResolveThread("beta"); err != nil || key != GroupKey(shared+"1111") {
		t.Errorf("by distinct name: key=%q err=%v", key, err)
	}
}

func TestGroupThreadsPersist(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	const ctxID = "abc123"
	if err := st.AppendGroupIncoming(ctxID, "Friends", "bob", "hey all"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendGroupOutgoing(ctxID, "Friends", "hi friends"); err != nil {
		t.Fatal(err)
	}

	thread, ok := st.Get(GroupKey(ctxID))
	if !ok || len(thread.Messages) != 2 {
		t.Fatalf("group thread wrong: ok=%v n=%d", ok, len(thread.Messages))
	}
	if thread.Title != "Friends" {
		t.Errorf("title = %q, want Friends", thread.Title)
	}
	if thread.Messages[0].Sender != "bob" {
		t.Errorf("incoming group sender = %q, want bob", thread.Messages[0].Sender)
	}
	if thread.Messages[1].Direction != Outgoing {
		t.Errorf("outgoing group message direction = %q", thread.Messages[1].Direction)
	}

	reloaded, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Get(GroupKey(ctxID)); !ok {
		t.Error("group thread lost after reload")
	}

	// List separates nothing by itself, but ordering must be stable.
	list := st.List()
	if len(list) != 1 || list[0].Key != GroupKey(ctxID) {
		t.Errorf("List = %+v", list)
	}
}

func TestCorruptFileRejected(t *testing.T) {
	chdirTemp(t)

	path := filepath.Join("corruptIdentity.mailbox.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("corruptIdentity"); err == nil {
		t.Fatal("expected error loading corrupt mailbox")
	}
}

func TestListSortedByActivity(t *testing.T) {
	chdirTemp(t)

	st, err := Load("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIncoming("old", "first"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendIncoming("new", "second"); err != nil {
		t.Fatal(err)
	}

	list := st.List()
	if len(list) != 2 {
		t.Fatalf("len(List) = %d", len(list))
	}
	// Same-millisecond writes tiebreak on key: "new" < "old".
	if list[0].Key != "new" {
		t.Errorf("expected newest thread first, got %q then %q", list[0].Key, list[1].Key)
	}
}
