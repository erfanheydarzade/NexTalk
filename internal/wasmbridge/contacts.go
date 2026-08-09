//go:build js && wasm

// Exposes internal/contacts to JS, mirroring cmd/contacts one-for-one:
// same Store type, same Add/Remove/Rename/SetNote/Get/Resolve mutations —
// just backed by st.Contacts (in-memory) instead of Store.Load()/Save()
// (os.ReadFile/os.WriteFile), which have no meaningful target in a
// browser sandbox. Same reasoning as identity.go's export/import split:
// JS owns persistence here too (exportContacts/importContacts), the Go
// side owns the mutations.
//
// Unlike identity/sessions, contacts carry no secrets, so there is
// nothing here for guard() to protect beyond the usual "don't panic the
// whole runtime" — see jsutil.go.
package wasmbridge

import (
	"encoding/json"
	"fmt"
	"sort"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/contacts"
)

// jsContactsAdd(name, userId) -> { name, user_id }
func jsContactsAdd(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	name, userID := argStr(args, 0), argStr(args, 1)
	if err := st.Contacts.Add(name, userID); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"name": name, "user_id": userID})
}

// jsContactsRemove(name) -> { ok: true }
func jsContactsRemove(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if err := st.Contacts.Remove(argStr(args, 0)); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// jsContactsRename(oldName, newName) -> { name, user_id }
func jsContactsRename(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	oldName, newName := argStr(args, 0), argStr(args, 1)
	if err := st.Contacts.Rename(oldName, newName); err != nil {
		return fail(err)
	}
	c, err := st.Contacts.Get(newName)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"name": c.Name, "user_id": c.UserID})
}

// jsContactsNote(name, note) -> { ok: true }
// An empty note clears it, same as `nextalk contacts note <name> ""`.
func jsContactsNote(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if err := st.Contacts.SetNote(argStr(args, 0), argStr(args, 1)); err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ok": true})
}

// jsContactsInfo(name) -> { name, user_id, note }
func jsContactsInfo(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	c, err := st.Contacts.Get(argStr(args, 0))
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"name": c.Name, "user_id": c.UserID, "note": c.Note})
}

// jsContactsList() -> { contacts: [{ name, user_id, note }, ...] } sorted by name.
func jsContactsList(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	names := make([]string, 0, len(st.Contacts.Contacts))
	for name := range st.Contacts.Contacts {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]any, 0, len(names))
	for _, name := range names {
		c := st.Contacts.Contacts[name]
		rows = append(rows, map[string]any{"name": c.Name, "user_id": c.UserID, "note": c.Note})
	}
	return ok(map[string]any{"contacts": rows})
}

// jsContactsResolve(nameOrId) -> { userId }
// Same fallback as internal/contacts.Store.Resolve: unknown names pass
// through unchanged, so callers can feed this straight into
// createOffer/connect wherever a peer ID is expected.
func jsContactsResolve(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	return ok(map[string]any{"userId": st.Contacts.Resolve(argStr(args, 0))})
}

// jsExportContacts() -> JSON string, for the caller to persist.
func jsExportContacts(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	data, err := json.Marshal(st.Contacts)
	if err != nil {
		return fail(err)
	}
	return string(data)
}

// jsImportContacts(json) -> { ok: true }
// Replaces the whole book, same shape Store.Load()/Save() persist
// (`{"contacts": {...}}`) — so a book exported by the CLI's contacts.json
// can be pasted in here unmodified, and vice versa.
func jsImportContacts(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	var loaded contacts.Store
	if err := json.Unmarshal([]byte(argStr(args, 0)), &loaded); err != nil {
		return fail(fmt.Errorf("parse contacts: %w", err))
	}
	if loaded.Contacts == nil {
		loaded.Contacts = make(map[string]contacts.Contact)
	}
	st.Contacts = &loaded
	return ok(map[string]any{"ok": true})
}
