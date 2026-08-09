//go:build js && wasm

// Session introspection. Nothing in cmd/worker or cmd/offline has a direct
// equivalent of this — the CLI is one-shot per invocation, so it never
// needs to ask "what sessions do I currently hold?" mid-process. A
// browser tab is long-lived, so the JS side needs a way to drive UI
// (peer list, pending-handshake badges, "forget this peer") off of
// st.Sessions without reaching into Go internals.
package wasmbridge

import (
	"sort"
	"strings"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/crypto"
)

// sessionStatus mirrors how handshake.go/listen.go use the sessions map:
// "pending_<peerId>" (and the single "pending" fallback) before the
// answer/finish step lands, the bare peerId key once RootKey is set.
func sessionStatus(peer *crypto.SecurePeer) string {
	if peer.RootKey == nil {
		return "pending"
	}
	return "established"
}

// jsListSessions() -> { sessions: [{ peerId, status }, ...] }
// peerId for a pending entry is the peer ID with any "pending_" prefix
// stripped; the bare "pending" placeholder (used when the peer ID isn't
// known yet, e.g. right after createOffer("")) is reported with peerId: "".
func jsListSessions(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	keys := make([]string, 0, len(st.Sessions))
	for k := range st.Sessions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := make([]any, 0, len(keys))
	for _, k := range keys {
		peerId := strings.TrimPrefix(k, "pending_")
		if k == "pending" {
			peerId = ""
		}
		rows = append(rows, map[string]any{
			"peerId": peerId,
			"status": sessionStatus(st.Sessions[k]),
		})
	}
	return ok(map[string]any{"sessions": rows})
}

// jsHasSession(peerId) -> { established: bool, pending: bool }
func jsHasSession(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	peerId := argStr(args, 0)
	established := false
	if peer, exists := st.Sessions[peerId]; exists {
		established = sessionStatus(peer) == "established"
	}
	_, pending := st.Sessions["pending_"+peerId]
	return ok(map[string]any{"established": established, "pending": pending})
}

// jsDropSession(peerId) -> { ok: true }
// Removes both the established entry (if any) and any matching pending_
// entry — e.g. to abandon a stalled handshake or forget a peer entirely.
// Does not touch the bare "pending" placeholder left by an anonymous
// createOffer(""); finishHandshake already clears that one itself.
func jsDropSession(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	peerId := argStr(args, 0)
	delete(st.Sessions, peerId)
	delete(st.Sessions, "pending_"+peerId)
	return ok(map[string]any{"ok": true})
}

// jsFingerprint(peerId) -> { fingerprint: "lusab-babad-..." }
// Human-pronounceable fingerprint of an established peer's identity
// public key, for the same out-of-band verification offline mode's
// proquint codec enables ("read me the five words on your screen") —
// just derived from a live session instead of a saved offer/answer blob.
func jsFingerprint(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	peer, exists := st.Sessions[argStr(args, 0)]
	if !exists {
		return failStr("session not found for peer " + argStr(args, 0))
	}
	return ok(map[string]any{"fingerprint": crypto.ToProquint(peer.IdentityPublicBytes())})
}
