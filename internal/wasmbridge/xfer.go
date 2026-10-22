//go:build js && wasm

// NexTalk.xfer.* and NexTalk.ticket.* — file transfer over a
// "binary-transfer" transport, via internal/filetransfer (whole-file E2E
// encryption -> chunks -> xfer-create/put/complete). Logic lives in
// internal/ntxhost; this file is js.Value glue.
//
// Honest limitation: WASM ABI v1 has no xfer operations, so a .wasm
// package that declares "binary-transfer" is accepted at install but
// xfer.* against it fails with a clear error. xfer.* works against any
// runtime that implements transport.FileTransport (tests use a fake).
package wasmbridge

import (
	"context"
	"fmt"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/ntxhost"
)

// progressArg finds a trailing JS function argument and wraps it. A throwing
// callback must never abort the transfer, so its panics are swallowed.
func progressArg(args []js.Value) ntxhost.Progress {
	if len(args) == 0 {
		return nil
	}
	fn := args[len(args)-1]
	if fn.Type() != js.TypeFunction {
		return nil
	}
	return func(done, total int) {
		defer func() { _ = recover() }()
		fn.Invoke(done, total)
	}
}

// send(id, peer, { name, data: base64, mailbox?, shard? }, onProgress?)
//
//	-> { ticket, transfer_id, expires }
func jsXferSend(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	o := argObj(args, 2)
	b64 := objStr(o, "data")
	// Reject before decoding: base64 inflates by 4/3.
	if len(b64) > ntxhost.MaxXferBytes*4/3+8 {
		return failStr(fmt.Sprintf("file too large (max %d bytes)", ntxhost.MaxXferBytes))
	}
	data, err := b64d(b64)
	if err != nil {
		return fail(fmt.Errorf("decode data: %w", err))
	}
	res, err := host.XferSend(context.Background(), id, ntxhost.XferSendParams{
		Peer: argStr(args, 1), Name: objStr(o, "name"), Data: data,
		Mailbox: objStr(o, "mailbox"), Shard: objStr(o, "shard"),
		Progress: progressArg(args),
	})
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"ticket": res.Ticket, "transfer_id": res.TransferID, "expires": res.Expires})
}

// receive(id, { ticket, from? }, onProgress?) -> { name, data: base64 }
func jsXferReceive(this js.Value, args []js.Value) any {
	id, bad := needID(args)
	if id == "" {
		return bad
	}
	o := argObj(args, 1)
	name, data, err := host.XferReceive(context.Background(), id, ntxhost.XferReceiveParams{
		Ticket: objStr(o, "ticket"), From: objStr(o, "from"), Progress: progressArg(args),
	})
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"name": name, "data": b64e(data)})
}

// ticket.describe(ticketB64) -> { transfer_id, shard, name, size, sender, expires }
// Display only: contacts nothing, never reveals the download secret.
// `expires` is always null — tickets do not carry an expiry.
func jsTicketDescribe(this js.Value, args []js.Value) any {
	info, err := ntxhost.DescribeTicket(argStr(args, 0))
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"transfer_id": info.TransferID, "shard": info.Shard, "name": info.Name,
		"size": info.Size, "sender": info.Sender, "expires": nil})
}
