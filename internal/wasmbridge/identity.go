//go:build js && wasm

package wasmbridge

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/crypto"
	"golang.org/x/crypto/ed25519"
)

// jsInit() -> { id }
// Generates a fresh identity and makes it the active one. Overwrites any
// previously active in-memory identity and drops any live relay
// connection — export first if you need the old identity back.
func jsInit(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail(err)
	}
	dilPriv, dilPub := crypto.GenerateDilithiumKeyPair()

	st.Id = crypto.DerivePeerID(pubEd, dilPub)
	st.IdentityPrivate = privEd
	st.IdentityPublic = pubEd
	st.DilithiumPrivate = dilPriv
	st.DilithiumPublic = dilPub
	st.Sessions = make(map[string]*crypto.SecurePeer)
	st.relayConn = nil
	st.relayKind = ""

	return ok(map[string]any{"id": st.Id})
}

// jsId() -> current peer id, or "" if no identity is loaded.
func jsId(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.Id
}

// jsExportIdentity() -> JSON string with the full identity + session
// state, for the caller to persist (localStorage, IndexedDB, ...). The
// live relay connection (if any) is not part of this — reconnect with
// connectWorker() after importing on the other side.
func jsExportIdentity(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Id == "" {
		return failStr("no identity loaded — call init() or importIdentity() first")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fail(err)
	}
	return string(data)
}

// jsImportIdentity(json) -> { id }
// Restores a previously exported identity, replacing the active one.
// Drops any live relay connection, same as init() — call connectWorker()
// again if you need one.
func jsImportIdentity(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	raw := argStr(args, 0)
	var loaded state
	if err := json.Unmarshal([]byte(raw), &loaded); err != nil {
		return fail(fmt.Errorf("parse identity: %w", err))
	}
	if loaded.Sessions == nil {
		loaded.Sessions = make(map[string]*crypto.SecurePeer)
	}
	loaded.eng = st.eng
	loaded.Contacts = st.Contacts // contacts are global, not per-identity — never clobbered by import
	loaded.relayConn = nil
	loaded.relayKind = ""
	*st = loaded

	return ok(map[string]any{"id": st.Id})
}
