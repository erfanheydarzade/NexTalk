//go:build js && wasm

// Local ratchet encrypt/decrypt for an already-established session. No
// networking here — see relay.go for actually moving bytes to a peer.
//
// Wire format: session.Encrypt/Decrypt (crypto/kex_hybrid.go) already
// nanopack-encode the SecureMessage frame (crypto/kex_hybrid_nanopack.go),
// exactly like every other NexTalk transport (offline/worker/proxy). This
// file only base64s that frame for JS; it never re-encodes it.
package wasmbridge

import (
	"fmt"
	"syscall/js"
	"unicode/utf8"

	"github.com/erfanheydarzade/NexTalk/crypto"
)

// messageBytes reads args[i] as the message body: a JS string (UTF-8) or
// { bytes: base64 } for binary payloads.
func messageBytes(args []js.Value, i int) ([]byte, error) {
	if i < len(args) && args[i].Type() == js.TypeObject {
		b := args[i].Get("bytes")
		if b.IsUndefined() || b.IsNull() {
			return nil, fmt.Errorf("message object needs a base64 `bytes` field")
		}
		raw, err := b64d(b.String())
		if err != nil {
			return nil, fmt.Errorf("decode message bytes: %w", err)
		}
		return raw, nil
	}
	return []byte(argStr(args, i)), nil
}

// jsEncrypt(peerId, message | { bytes: base64 }) -> { ciphertext: base64 }
// A string message is UTF-8; pass { bytes } for binary payloads.
func jsEncrypt(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	peerId := argStr(args, 0)
	message, merr := messageBytes(args, 1)
	if merr != nil {
		return fail(merr)
	}

	session, exists := st.Sessions[peerId]
	if !exists {
		return failStr("session not found for peer " + peerId)
	}
	ciphertext, err := session.Encrypt(st.Id, message)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ciphertext": b64e(ciphertext)})
}

// jsDecrypt(payloadB64) -> { senderId, plaintext, encoding }
// encoding is "utf-8" (plaintext is the string) or "base64" (plaintext is
// the base64 of non-UTF-8 bytes).
func jsDecrypt(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	payload, err := b64d(argStr(args, 0))
	if err != nil {
		return fail(fmt.Errorf("decode payload: %w", err))
	}

	claimedSender, err := crypto.SenderIDFromFrame(payload)
	if err != nil {
		return fail(err)
	}
	session, exists := st.Sessions[claimedSender]
	if !exists {
		return failStr("no active session with peer " + claimedSender)
	}
	senderID, plaintext, err := session.Decrypt(payload)
	if err != nil {
		return fail(err)
	}
	if utf8.Valid(plaintext) {
		return ok(map[string]any{"senderId": senderID, "plaintext": string(plaintext), "encoding": "utf-8"})
	}
	return ok(map[string]any{"senderId": senderID, "plaintext": b64e(plaintext), "encoding": "base64"})
}
