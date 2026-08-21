# NexTalk in the browser (WebAssembly)

`cmd/nextalk-wasm` compiles NexTalk to WASM and exposes it to JavaScript
as a global `NexTalk` object. It reuses the same `core.Engine` +
`crypto.SecurePeer` as the CLI, and — as of this revision — the same
Router/shard relay `nextalk worker` uses, live from the browser.

## Layout

All logic lives in `internal/wasmbridge`, one small file per concern —
not one large `main.go`:

```
internal/wasmbridge/
  state.go       shared in-memory state (the wasm analogue of client.Client)
  jsutil.go      generic Go <-> js.Value plumbing, no protocol logic
  identity.go    init / id / exportIdentity / importIdentity
  handshake.go   createOffer / acceptOffer / finishHandshake
  message.go     encrypt / decrypt (local ratchet, no networking)
  relay.go       optional live transport: connectWorker / send* / receive
  listen.go      auto-dispatching poll, mirrors `nextalk worker listen`
  encoding.go    proquint helpers (parity with offline mode's codec)
  contacts.go    NexTalk.contacts.* — same internal/contacts.Store as `nextalk contacts`
  sessions.go    NexTalk.sessions.* — introspection over st.Sessions, fingerprinting
  context.go     NexTalk.context.* — multi-message context management (fan-out)
  version.go     NexTalk.version() — build/API-revision info
  register.go    wires every js.FuncOf above onto the `NexTalk` JS global

cmd/nextalk-wasm/main.go   build tag + wasmbridge.Register() + select{}
```

Each concern gets its own file, the same way `cmd/worker` is split across
`worker.go` / `register.go` / `envolpe.go` / `connect.go` / `encrypt.go` /
... instead of one command doing everything, and the same way `cmd/offline`
splits `offer.go` / `accept.go` / `finish.go` / `encrypt.go` / `decrypt.go`.
`register.go` is the wasm build's answer to that pattern: it is the one
place that ever mounts a new call onto the `NexTalk` global, mirroring how
`cmd/root.go` is the one place every CLI command group gets mounted onto
the root `cobra.Command`.

`main.go` carries no protocol logic, so growing the JS surface never
means growing `main.go`.

## Why the relay "just works" in wasm

Earlier drafts of this feature assumed the CLI's `worker`/`proxy`
transports couldn't be reused because they use `net/http`, which used to
need OS sockets. That's no longer the constraint: since **Go 1.21**,
`net/http` under `GOOS=js GOARCH=wasm` transparently uses the browser's
`fetch()` API as its `RoundTripper` (`net/http/roundtrip_js.go` in the Go
source tree). `go.mod` here targets Go 1.25, well past that.

So `internal/relay/worker.Adapter` — the exact same Router-client +
shard-HTTP code `cmd/worker` uses — compiles and runs unmodified under
wasm. Nothing about Router discovery, mailbox capability caching, replica
fallback, or sender-auth signing needed to be reimplemented for the
browser; `internal/wasmbridge/relay.go` just constructs one and drives it
with the same helpers `cmd/worker` uses:

- `relay.SendEnvelope(ctx, r, senderPriv, recipientPubKey, type, data)`
  and `relay.WrapEnvelope`/`relay.PeerIDToEd25519Pub` — promoted out of
  what used to be `cmd/worker`-private `envolpe.go` into
  `internal/relay/relay.go`, so both the CLI and the wasm bridge call the
  *same* function instead of two copies that could drift.
- `workerrelay.UnwrapEnvelope` — already exported, unchanged.

**Not wired up:** the proxy transport. `internal/relay/proxy.Adapter.Send`
doesn't actually satisfy `relay.Relay` today (its signature is missing
the `senderPriv` parameter the interface requires), so nothing in the
existing codebase — worker transport included — can use it
polymorphically yet. That's a pre-existing gap, not something the wasm
build introduced; flagging it here rather than papering over it inside
the bridge.

**Still not included:** `internal/registry`, the CLI's transport-picker
registry behind `nextalk shell` — it assumes a terminal REPL loop, which
has no browser-tab equivalent. The bridge's own `register.go` plays the
analogous role (one explicit place that wires up every JS-visible
function), just without the `init()`-blank-import auto-discovery the CLI
registry uses, since a browser tab doesn't need to offer a menu of
multiple transports the way an interactive shell does — JS decides what
to wire up by calling `NexTalk.relay.connectWorker(...)` or not.

`internal/contacts` **is** wired up (`NexTalk.contacts.*`, see below) —
same `Store` type `nextalk contacts` uses, same mutations, just backed by
in-memory state instead of `Store.Load()`/`Store.Save()`'s
`os.ReadFile`/`os.WriteFile`, which have no target in a browser sandbox.
JS owns persistence via `exportContacts()`/`importContacts()`, same
split as identity.

## Building

```bash
./cmd/nextalk-wasm/build.sh            # -> web/wasm/{nextalk.wasm,wasm_exec.js}
./cmd/nextalk-wasm/build.sh dist/wasm  # custom output dir
```

Requires a Go toolchain with `GOOS=js GOARCH=wasm` support (Go 1.25, same
as `go.mod`). Everything the wasm build pulls in (`circl`, `x/crypto`,
`mr-tron/base58`, `erfanheydarzade/nanopack`) is pure Go — no cgo, no
platform syscalls beyond what `syscall/js` (and, transitively, `fetch`
via `net/http`) provides.

## Loading it

```html
<script src="wasm_exec.js"></script>
<script>
  const go = new Go();
  WebAssembly.instantiateStreaming(fetch("nextalk.wasm"), go.importObject)
    .then((result) => {
      go.run(result.instance);
      // window.NexTalk is now available
    });
</script>
```

## Serving it: why `file://` doesn't work

Opening `web/index.html` directly by double-clicking it (a `file://…`
URL) will **not** work — you'll see the page but `NexTalk` will never
appear, usually with `fetch` or CORS errors in the console. This isn't a
NexTalk bug, it's the browser:

- `WebAssembly.instantiateStreaming(fetch("nextalk.wasm"), ...)` requires
  `fetch()` to actually succeed. Under `file://`, most browsers refuse to
  `fetch()` a sibling file at all (no HTTP response = no `Content-Type`,
  which `instantiateStreaming` needs), and Chrome additionally blocks
  cross-origin-looking requests between local files as a CORS violation.
- `nextalk.wasm` is ~11 MB uncompressed. Streaming compilation
  (`instantiateStreaming`) starts compiling as bytes arrive; without it
  the whole file must download and buffer before compilation can even
  start, which is slow and, over `file://`, doesn't happen reliably
  anyway.

The fix is always the same: **serve the directory over HTTP**, even
locally. From the repo root (after running `./cmd/nextalk-wasm/build.sh`,
see below):

```bash
python3 -m http.server 8000
```

then open **http://localhost:8000/web/** — not `web/index.html` via the
file picker. Any static file server works identically (`npx serve`,
`caddy file-server`, nginx, etc.) — `python3 -m http.server` is just the
one guaranteed to already be on your machine. This applies to *any* page
that loads `nextalk.wasm`, not just the bundled demo — plan on a real
(even if purely local) HTTP server for every environment you run this
in, including CI smoke tests.

If you deploy `web/` to a real host (GitHub Pages, S3, nginx, ...), make
sure it serves `.wasm` with `Content-Type: application/wasm` — most
static hosts do this automatically, but if `instantiateStreaming` throws
a `CompileError` about the response's MIME type, that's the header to
check first.

## JS API

All calls are synchronous and return either a plain object or
`{ error: "..." }` — check `.error` before using the result.

```js
// Identity
NexTalk.init()                     // -> { id }             new identity, replaces active one
NexTalk.id()                       // -> "3xk9...s"          current peer id, or ""
NexTalk.exportIdentity()           // -> JSON string          persist this (localStorage, IDB, ...)
NexTalk.importIdentity(json)       // -> { id }               restore a previously exported identity

// Handshake (payloads are base64-encoded JSON; move them however you like,
// or hand them straight to NexTalk.relay.send* below)
NexTalk.createOffer(peerId)        // -> { offer }
NexTalk.acceptOffer(offerB64)      // -> { senderId, answer }
NexTalk.finishHandshake(answerB64) // -> { peerId }

// Messaging (requires an established session with peerId)
NexTalk.encrypt(peerId, text)      // -> { ciphertext }       ciphertext is base64, nanopack-framed
NexTalk.decrypt(payloadB64)        // -> { senderId, plaintext }

// Relay — the same Router/shard network `nextalk worker` uses
NexTalk.relay.connectWorker(routerUrl) // -> { ok }                            synchronous
NexTalk.relay.disconnect()             // -> { ok }                            synchronous
NexTalk.relay.status()                 // -> { connected, kind }               synchronous
await NexTalk.relay.register()         // -> { pubkey }                        async; optional, send/receive register lazily too
await NexTalk.relay.sendOffer(peerId, offerB64)     // -> { ok }              async
await NexTalk.relay.sendAnswer(peerId, answerB64)   // -> { ok }              async
await NexTalk.relay.sendMessage(peerId, cipherB64)  // -> { ok }              async
await NexTalk.relay.receive()          // -> { envelopes: [{ type, data }, ...] }  async
                                       //    type: 1=offer 2=answer 3=message; data is base64,
                                       //    feed straight into acceptOffer/finishHandshake/decrypt.

// Encoding — parity with offline mode's human-readable codec
NexTalk.encoding.toProquint(base64)    // -> { proquint: "lusab-babad-..." }
NexTalk.encoding.fromProquint(words)   // -> { data: base64 }

// Offline mode — createOffer/acceptOffer/finishHandshake/encrypt/decrypt
// above ARE offline mode: no networking happens in any of them, same as
// `nextalk offline`. This namespace is the same five functions under the
// names that match `nextalk offline offer/accept/finish/encrypt/decrypt`,
// for callers who never touch NexTalk.relay.* and want that made explicit
// rather than inferring it from the absence of a relay call.
NexTalk.offline.offer(peerId)          // === createOffer
NexTalk.offline.accept(offerB64)       // === acceptOffer
NexTalk.offline.finish(answerB64)      // === finishHandshake
NexTalk.offline.encrypt(peerId, text)  // === encrypt
NexTalk.offline.decrypt(payloadB64)    // === decrypt
// Move offer/answer/ciphertext blobs out-of-band however you like — copy/
// paste, QR code, USB stick — exactly like the CLI's `-o file` / `--out b64`.

// Contacts — global address book, same internal/contacts.Store as
// `nextalk contacts`. No identity required.
NexTalk.contacts.add(name, userId)         // -> { name, user_id }
NexTalk.contacts.remove(name)              // -> { ok }
NexTalk.contacts.rename(oldName, newName)  // -> { name, user_id }
NexTalk.contacts.note(name, text)          // -> { ok }              "" clears it
NexTalk.contacts.info(name)                // -> { name, user_id, note }
NexTalk.contacts.list()                    // -> { contacts: [{ name, user_id, note }, ...] }
NexTalk.contacts.resolve(nameOrId)         // -> { userId }           passthrough if unknown
NexTalk.contacts.export()                  // -> JSON string          persist this
NexTalk.contacts.import(json)              // -> { ok }               same shape as contacts.json

// Sessions — introspection over the live session map (createOffer/
// acceptOffer/finishHandshake populate it; nothing in the CLI needs this
// since each invocation is one-shot, but a long-lived browser tab does).
NexTalk.sessions.list()          // -> { sessions: [{ peerId, status }, ...] }  status: "pending" | "established"
NexTalk.sessions.has(peerId)     // -> { established, pending }
NexTalk.sessions.drop(peerId)    // -> { ok }                         forget a peer / abandon a stalled handshake
NexTalk.sessions.fingerprint(peerId) // -> { fingerprint }             proquint of the peer's identity key, for out-of-band verification

// Contexts — multi-message fan-out over independent 1:1 secure channels.
// This is NOT a group chat protocol — each recipient gets an independent
// ciphertext via their existing 1:1 session with the sender.
NexTalk.context.createContext(name)              // -> { context_id, display_name, version, creator_id }
NexTalk.context.list()                           // -> [{ context_id, display_name, version, creator_id }, ...]
NexTalk.context.addMember(contextId, peerId)     // -> { ok }
NexTalk.context.excludeMember(contextId, peerId) // -> { ok }               local delivery exclusion
NexTalk.context.includeMember(contextId, peerId) // -> { ok }               re-enable excluded member
NexTalk.context.listMembers(contextId)           // -> [{ peer_id, policy }, ...]
NexTalk.context.sendMulti(contextId, message)    // -> { message_id, deliveries: [{ recipient, status, error }], sent, pending, failed }
NexTalk.context.getEffectiveRecipients(contextId) // -> [peer_id, ...]

// Misc
NexTalk.version()                // -> { version, api }               build tag + JS-surface revision
```

### Example: two real browser peers, over the worker relay

```js
NexTalk.init();
NexTalk.relay.connectWorker("https://router.example.com");
await NexTalk.relay.register();

// ... obtain the other peer's id out of band (they ran NexTalk.id()) ...
const { offer } = NexTalk.createOffer(otherPeerId);
await NexTalk.relay.sendOffer(otherPeerId, offer);

// Poll periodically (e.g. setInterval) on both sides:
const { envelopes } = await NexTalk.relay.receive();
for (const env of envelopes) {
  if (env.type === 1) {
    const { senderId, answer } = NexTalk.acceptOffer(env.data);
    await NexTalk.relay.sendAnswer(senderId, answer);
  } else if (env.type === 2) {
    const { peerId } = NexTalk.finishHandshake(env.data);
    await NexTalk.relay.sendMessage(peerId, NexTalk.encrypt(peerId, "hi!").ciphertext);
  } else if (env.type === 3) {
    const { senderId, plaintext } = NexTalk.decrypt(env.data);
    console.log(senderId, plaintext);
  }
}
```

### Example: two identities in one tab (self-handshake, for local testing)

```js
NexTalk.init();
const bob = NexTalk.id();
const bobExport = NexTalk.exportIdentity();

NexTalk.init();
const alice = NexTalk.id();
const aliceExport = NexTalk.exportIdentity();

const { offer } = NexTalk.createOffer(bob);

NexTalk.importIdentity(bobExport);
const { answer } = NexTalk.acceptOffer(offer);

NexTalk.importIdentity(aliceExport);
NexTalk.finishHandshake(answer);
const { ciphertext } = NexTalk.encrypt(bob, "hello");
```

A single Go/wasm instance holds one active identity at a time (mirrors
the CLI's single-active-`Client` model). Juggling multiple identities in
one page means swapping via `exportIdentity`/`importIdentity` — fine for
a demo/tab-per-peer setup; a session-keyed registry replacing the single
global `state` is the natural next step for a real multi-identity UI (see
`web/index.html` for a two-tab, real-relay demo built on top of exactly
this API).

## Where this goes next

- Multiple concurrent identities in one page without export/import
  juggling (replace the single global `state` with a session-keyed map).
- WebSocket transport as an alternative to the worker relay's HTTP
  polling, for push instead of poll.
- Binary message payloads (`encrypt`/`decrypt` currently treat messages
  as UTF-8 text — base64 on the JS side first for binary data).
- Fix `internal/relay/proxy.Adapter.Send`'s signature so the proxy
  transport can be wired up the same way the worker one now is.
- `NexTalk.sessions.fingerprint` only covers established sessions today
  (it reads the negotiated peer's identity key out of `st.Sessions`); a
  pre-handshake fingerprint straight off an offer/answer blob — the
  `offline accept`-time trust decision the CLI supports — would need its
  own entry point since there's no session to look one up on yet.
