//go:build js && wasm

// Package wasmbridge is the wasm build's JS boundary. It is the browser
// equivalent of client.Client + a CLI transport (cmd/worker, cmd/offline,
// ...) combined — but split into one small file per concern instead of one
// monolithic main.go, the same way cmd/worker itself is split across
// worker.go / register.go / envolpe.go / connect.go / encrypt.go / ...
//
//	state.go       shared in-memory state + its JSON shape
//	jsutil.go      generic Go <-> js.Value plumbing (no protocol logic)
//	identity.go    init / id / exportIdentity / importIdentity
//	handshake.go   createOffer / acceptOffer / finishHandshake
//	message.go     encrypt / decrypt (local ratchet, no networking)
//	relay.go       optional live transport: connectWorker / send* / receive
//	listen.go      auto-dispatching poll, mirrors `nextalk worker listen`
//	encoding.go    proquint helpers, for parity with offline mode's codec
//	contacts.go    NexTalk.contacts.* — same internal/contacts.Store as `nextalk contacts`
//	sessions.go    NexTalk.sessions.* — introspection over st.Sessions, fingerprinting
//	context.go     NexTalk.context.* — multi-message context management
//	version.go     NexTalk.version() — build/API-revision info
//	register.go    wires every js.FuncOf above onto the `NexTalk` JS global
//
// cmd/nextalk-wasm/main.go itself is now just a build-tag + Register() call.
package wasmbridge

import (
	"sync"

	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/contacts"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"golang.org/x/crypto/ed25519"
)

// state is the in-memory analogue of client.Client, minus disk persistence
// (client.SaveClient/LoadClient shell out to os.ReadFile/os.WriteFile,
// which have no meaningful target in a browser sandbox). The JS side owns
// persistence: call exportIdentity() and stash the result wherever it
// likes (localStorage, IndexedDB, ...), then importIdentity() to resume.
type state struct {
	mu sync.Mutex

	Id               string             `json:"id"`
	IdentityPrivate  ed25519.PrivateKey `json:"identityPrivate"`
	IdentityPublic   ed25519.PublicKey  `json:"identityPublic"`
	DilithiumPrivate []byte             `json:"dilithiumPrivate"`
	DilithiumPublic  []byte             `json:"dilithiumPublic"`

	Sessions map[string]*crypto.SecurePeer `json:"sessions"`

	// Contacts is the wasm build's in-memory analogue of internal/contacts'
	// on-disk store: same Store type (reused, not reimplemented — see
	// contacts.go), just never Load()/Save()'d to a filesystem the browser
	// doesn't have. JS owns persistence the same way it does for identity:
	// exportContacts()/importContacts(), stash it wherever it likes.
	//
	// Deliberately its own field rather than folded into exportIdentity's
	// JSON: contacts are a global address book, not part of any one
	// identity (see internal/contacts' package doc), so an identity
	// import/export must not clobber it.
	Contacts *contacts.Store `json:"-"`

	eng *core.Engine

	// Live relay connection, if any. Deliberately excluded from the JSON
	// export — it's a runtime handle, not identity/session data, and a
	// fresh page load reconnects explicitly via connectWorker() rather
	// than trying to resurrect an http.Client-ish thing from JSON.
	relayConn relay.Relay `json:"-"`
	relayKind string      `json:"-"` // "worker" | "" (not connected)

	// Multi-message fanout state. These are in-memory only (no browser
	// filesystem) and are initialized when the first context operation
	// is requested.
	ContextStore  multimsg.ContextStore  `json:"-"`
	DeliveryStore multimsg.DeliveryStore `json:"-"`
	Fanout        *multimsg.Fanout       `json:"-"`
}

var st = &state{
	eng:      core.NewEngine(),
	Contacts: &contacts.Store{Contacts: make(map[string]contacts.Contact)},
}
