package multimsg

import (
	"os"
	"testing"
)

// TestFileStoreLegacyJSONMigration pins the one-time migration from the
// pre-nanopack *.json store layout: legacy files are READ once, their data
// lands in the .np stores, and subsequent opens use only the new format.
func TestFileStoreLegacyJSONMigration(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if os.Chdir(dir) == nil {
		defer os.Chdir(oldWd)
	}

	const id = "migratee"
	ctxsFile := id + ".contexts.json"
	polsFile := id + ".policies.json"
	delFile := id + ".deliveries.json"

	if err := os.WriteFile(ctxsFile, []byte(`[
	  {"context_id":"cafe1111","display_name":"Legacy Crew","metadata_version":3,
	   "creator_id":"alicePeer","signature":"AAEC"}
	]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(polsFile, []byte(`[
	  {"context_id":"cafe1111","recipient":"bobPeer","policy":2,"updated_at":1700000000000}
	]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(delFile, []byte(`[
	  {"delivery_id":"d1","message_id":"m1","recipient":"bobPeer","channel_id":"bobPeer",
	   "ciphertext":"AAE=","context_id":"cafe1111","timestamp":1700000001000}
	]`), 0600); err != nil {
		t.Fatal(err)
	}

	ctxStore, err := NewFileContextStore(ctxsFile, polsFile)
	if err != nil {
		t.Fatalf("migrating context store: %v", err)
	}
	meta, err := ctxStore.LoadContext("cafe1111")
	if err != nil || meta.DisplayName != "Legacy Crew" || meta.MetadataVersion != 3 {
		t.Fatalf("context not migrated: %+v %v", meta, err)
	}
	pol, err := ctxStore.LoadPolicy("cafe1111", "bobPeer")
	if err != nil || pol.Policy != PolicyBlocked {
		t.Fatalf("policy not migrated: %+v %v", pol, err)
	}

	delStore, err := NewFileDeliveryStore(delFile)
	if err != nil {
		t.Fatalf("migrating delivery store: %v", err)
	}
	d1, err := delStore.LoadDelivery("d1")
	if err != nil || d1.ContextID != "cafe1111" || string(d1.Ciphertext) != "\x00\x01" {
		t.Fatalf("delivery not migrated: %+v %v", d1, err)
	}

	// Reopen: everything must come from the .np files now.
	ctxStore2, err := NewFileContextStore(ctxsFile, polsFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctxStore2.LoadContext("cafe1111"); err != nil {
		t.Fatalf("np reload lost context: %v", err)
	}
	if _, err := os.Stat(id + ".contexts.np"); err != nil {
		t.Errorf("contexts.np missing after migration: %v", err)
	}
	// Legacy files are preserved on disk — migration never deletes user data.
	for _, f := range []string{ctxsFile, polsFile, delFile} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("legacy %s should be preserved: %v", f, err)
		}
	}
}
