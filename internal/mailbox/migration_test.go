package mailbox

import (
	"os"
	"testing"
)

// TestLegacyJSONMigration is the one-time-migration guarantee: a mailbox
// written by a pre-nanopack build (<id>.mailbox.json) must be loaded
// transparently and re-persisted as <id>.mailbox.np, preserving messages,
// unread flags, titles and group keys.
func TestLegacyJSONMigration(t *testing.T) {
	chdirTemp(t)

	const identity = "legacyUser"
	legacy := legacyFileFor(identity)
	old := `[
	  {"key":"alicePeer","messages":[
	    {"id":"1","direction":"in","kind":"dm","body":"hello from json era","timestamp":1700000000000,"is_read":false}
	  ]},
	  {"key":"ctx:abc123","title":"Old Crew","messages":[
	    {"id":"2","direction":"in","kind":"group","body":"group msg","timestamp":1700000001000,"is_read":false,
	     "sender":"bobPeer","context_id":"abc123","context_name":"Old Crew"},
	    {"id":"3","direction":"out","kind":"group","body":"my reply","timestamp":1700000002000,"is_read":true,
	     "sender":"Me","context_id":"abc123","context_name":"Old Crew"}
	  ]}
	]`
	if err := os.WriteFile(legacy, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}

	st, err := Load(identity)
	if err != nil {
		t.Fatalf("migrating load: %v", err)
	}

	dm, ok := st.Get("alicePeer")
	if !ok || len(dm.Messages) != 1 || dm.Messages[0].Body != "hello from json era" {
		t.Fatalf("DM thread not migrated: %+v", dm)
	}
	if dm.Messages[0].IsRead {
		t.Error("unread flag lost in migration")
	}

	group, ok := st.Get(GroupKey("abc123"))
	if !ok || len(group.Messages) != 2 || group.Title != "Old Crew" {
		t.Fatalf("group thread not migrated: %+v", group)
	}

	// The new-format file must now exist with the same content…
	if _, err := os.Stat(fileFor(identity)); err != nil {
		t.Fatalf("migrated .np store missing: %v", err)
	}
	reloaded, err := Load(identity)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.UnreadTotal(); got != 2 { // two unread incoming msgs
		t.Errorf("UnreadTotal after reload = %d, want 2", got)
	}
	if _, ok := reloaded.Get(GroupKey("abc123")); !ok {
		t.Error("group thread lost across np reload")
	}

	// …and the legacy file is left untouched on disk (never deleted for you).
	if _, err := os.Stat(legacy); err != nil {
		t.Error("legacy file should be preserved after migration")
	}
}
