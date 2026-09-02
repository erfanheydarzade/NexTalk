//go:build js && wasm

package wasmbridge

import "syscall/js"

// Register builds the `NexTalk` global JS object and installs it. It is
// the ONLY thing cmd/nextalk-wasm/main.go calls — main.go itself carries
// no protocol logic, so growing the JS surface never means growing
// main.go.
func Register() {
	ns := js.Global().Get("Object").New()

	// identity.go
	ns.Set("init", js.FuncOf(guard(jsInit)))
	ns.Set("exportIdentity", js.FuncOf(guard(jsExportIdentity)))
	ns.Set("importIdentity", js.FuncOf(guard(jsImportIdentity)))
	ns.Set("id", js.FuncOf(guard(jsId)))

	// handshake.go
	ns.Set("createOffer", js.FuncOf(guard(jsCreateOffer)))
	ns.Set("acceptOffer", js.FuncOf(guard(jsAcceptOffer)))
	ns.Set("finishHandshake", js.FuncOf(guard(jsFinishHandshake)))

	// message.go
	ns.Set("encrypt", js.FuncOf(guard(jsEncrypt)))
	ns.Set("decrypt", js.FuncOf(guard(jsDecrypt)))

	// relay.go — grouped under NexTalk.relay.* so it reads as clearly
	// optional/pluggable, distinct from the pure-crypto calls above.
	relayNs := js.Global().Get("Object").New()
	relayNs.Set("connectWorker", js.FuncOf(guard(jsConnectWorker)))
	relayNs.Set("disconnect", js.FuncOf(guard(jsDisconnectRelay)))
	relayNs.Set("status", js.FuncOf(guard(jsRelayStatus)))
	relayNs.Set("register", js.FuncOf(async(guard(jsRegisterWithRelay))))
	relayNs.Set("sendOffer", js.FuncOf(async(guard(jsSendOffer))))
	relayNs.Set("sendAnswer", js.FuncOf(async(guard(jsSendAnswer))))
	relayNs.Set("sendMessage", js.FuncOf(async(guard(jsSendMessage))))
	relayNs.Set("receive", js.FuncOf(async(guard(jsReceive))))
	relayNs.Set("listen", js.FuncOf(async(guard(jsListen)))) // listen.go — auto-dispatching, mirrors `nextalk worker listen`
	ns.Set("relay", relayNs)

	// encoding.go — also namespaced, same reasoning.
	encodingNs := js.Global().Get("Object").New()
	encodingNs.Set("toProquint", js.FuncOf(guard(jsToProquint)))
	encodingNs.Set("fromProquint", js.FuncOf(guard(jsFromProquint)))
	ns.Set("encoding", encodingNs)

	// contacts.go — global address book, same Store as `nextalk contacts`.
	contactsNs := js.Global().Get("Object").New()
	contactsNs.Set("add", js.FuncOf(guard(jsContactsAdd)))
	contactsNs.Set("remove", js.FuncOf(guard(jsContactsRemove)))
	contactsNs.Set("rename", js.FuncOf(guard(jsContactsRename)))
	contactsNs.Set("note", js.FuncOf(guard(jsContactsNote)))
	contactsNs.Set("info", js.FuncOf(guard(jsContactsInfo)))
	contactsNs.Set("list", js.FuncOf(guard(jsContactsList)))
	contactsNs.Set("resolve", js.FuncOf(guard(jsContactsResolve)))
	contactsNs.Set("export", js.FuncOf(guard(jsExportContacts)))
	contactsNs.Set("import", js.FuncOf(guard(jsImportContacts)))
	ns.Set("contacts", contactsNs)

	// context.go — multi-message context management (fan-out over 1:1 channels).
	contextNs := js.Global().Get("Object").New()
	contextNs.Set("createContext", js.FuncOf(guard(jsContextCreateContext)))
	contextNs.Set("list", js.FuncOf(guard(jsContextList)))
	contextNs.Set("show", js.FuncOf(guard(jsContextShow)))
	contextNs.Set("rename", js.FuncOf(guard(jsContextRename)))
	contextNs.Set("addMember", js.FuncOf(guard(jsContextAddMember)))
	contextNs.Set("excludeMember", js.FuncOf(guard(jsContextExcludeMember)))
	contextNs.Set("includeMember", js.FuncOf(guard(jsContextIncludeMember)))
	contextNs.Set("muteMember", js.FuncOf(guard(jsContextMute)))
	contextNs.Set("blockMember", js.FuncOf(guard(jsContextBlock)))
	contextNs.Set("removeMember", js.FuncOf(guard(jsContextRemoveMember)))
	contextNs.Set("listMembers", js.FuncOf(guard(jsContextListMembers)))
	contextNs.Set("sendMulti", js.FuncOf(guard(jsContextSendMulti)))
	contextNs.Set("getEffectiveRecipients", js.FuncOf(guard(jsContextGetEffectiveRecipients)))
	contextNs.Set("drop", js.FuncOf(guard(jsContextDrop)))
	ns.Set("context", contextNs)

	// sessions.go — introspection over st.Sessions; nothing here mutates
	// crypto state except dropSession's delete.
	sessionsNs := js.Global().Get("Object").New()
	sessionsNs.Set("list", js.FuncOf(guard(jsListSessions)))
	sessionsNs.Set("has", js.FuncOf(guard(jsHasSession)))
	sessionsNs.Set("drop", js.FuncOf(guard(jsDropSession)))
	sessionsNs.Set("fingerprint", js.FuncOf(guard(jsFingerprint)))
	ns.Set("sessions", sessionsNs)

	// offline.go — same createOffer/acceptOffer/finishHandshake/encrypt/
	// decrypt calls above, aliased under the name that matches
	// `nextalk offline`'s mental model (no relay involved) for callers
	// who never touch NexTalk.relay.* at all.
	offlineNs := js.Global().Get("Object").New()
	offlineNs.Set("offer", js.FuncOf(guard(jsCreateOffer)))
	offlineNs.Set("accept", js.FuncOf(guard(jsAcceptOffer)))
	offlineNs.Set("finish", js.FuncOf(guard(jsFinishHandshake)))
	offlineNs.Set("encrypt", js.FuncOf(guard(jsEncrypt)))
	offlineNs.Set("decrypt", js.FuncOf(guard(jsDecrypt)))
	ns.Set("offline", offlineNs)

	// version/info — parity with the CLI always having a --version / a
	// known binary identity; useful for JS to sanity-check it loaded the
	// build it expected.
	ns.Set("version", js.FuncOf(guard(jsVersion)))

	js.Global().Set("NexTalk", ns)
}
