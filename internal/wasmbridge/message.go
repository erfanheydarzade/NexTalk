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

	"github.com/erfanheydarzade/NexTalk/crypto"
)

// jsEncrypt(peerId, message) -> { ciphertext: base64 }
// message is treated as a UTF-8 JS string; for binary payloads, base64 the
// bytes on the JS side first.
func jsEncrypt(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	peerId := argStr(args, 0)
	message := argStr(args, 1)

	session, exists := st.Sessions[peerId]
	if !exists {
		return failStr("session not found for peer " + peerId)
	}
	ciphertext, err := session.Encrypt(st.Id, []byte(message))
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ciphertext": b64e(ciphertext)})
}

// jsDecrypt(payloadB64) -> { senderId, plaintext }
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
	return ok(map[string]any{"senderId": senderID, "plaintext": string(plaintext)})
}
