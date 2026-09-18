# NexTalk Runtime Transport Management System — Design

Status: `implemented`. All components below ship and are exercised by
automated tests plus the real-binary scenario in `docs/real-scenario.md`:
external-process transports, WASM transports, shared dispatch, FileRelay
message + file bridges, and the relay-example third-party template.

## 0. What shipped (v1 + v2)

- `internal/transport`: manifest, NanoPack RPC (schemas 100–126, ops 1–15
  + op-0 errors), process runtime, **WASM runtime (wazero)**, manager
  (install/enable/disable/remove/config/attach/state/hash-pinning),
  `FrameTransport` + `FileTransport` interfaces, capability routing.
- `internal/dispatch`: the single shared receive path; `worker listen`
  (CLI) and the worker shell now delegate to it.
- `cmd/transport`: list/install/remove/enable/disable/status/poll/
  send-frame/attach/detach/register/resolve/xfer-send/xfer-recv.
- `internal/filetransfer`: whole-file E2E encrypt → chunk →
  verify → decrypt (8 MiB cap documented).
- `example-transports/relay-example`: standalone third-party module
  (own go.mod) proving the no-rebuild template.
- NexTalk-FileRelay: `transports/filerelay` courier bridge
  (`message` + `binary-transfer`) and `cmd/filerelayd` runnable server.

## 1. Where transport assumptions live today

| Location | Assumption | Problem |
|---|---|---|
| `internal/relay/relay.go` — `Relay{Register,Send,Receive}` | transport receives the user's **private key** (`senderPriv`, `privateKey`) | external/untrusted transport must never see identity keys |
| `internal/registry/state.go` — `State.Worker relay.Relay` | exactly one hardcoded relay, in-process | no multi-transport, no lifecycle |
| `internal/registry/registry.go` + `cmd/transports/state.go` | transports self-register via `init()` + blank import | adding a transport = source change + rebuild |
| `cmd/worker`, `cmd/proxy`, `cmd/offline` | CLI+GUI faces compiled in | same rebuild coupling |
| `internal/frame` type bytes `0x01..0x04` | the one sound idea: a transport-agnostic frame vocabulary | **keep** — capability `message` routes these frames |
| `transport/` legacy JSON clients, `internal/config` env URLs | config baked into env, no schema | replace with per-transport config blobs |
| No manifest / versions / sandbox anywhere | — | new: `internal/transport` |

## 2. Decision: external transport processes (Option 1)

- **Rejected: native plugins (.so/.dll).** No isolation, no portability
  (Windows/macOS/Linux × amd64/arm64 matrix), version-skew crashes inside
  the crypto process. Worst fit for an untrusted-network messenger.
- **Deferred: WASM transports.** Good sandbox story, but needs a WASM
  runtime + WASI socket story inside the CLI; do it after the process
  model proves the API.
- **Chosen (both ship): external processes** for full transports, **WASM
  modules (wazero)** for sandboxed queue-model transports. Strong OS or
  VM-level isolation, language-independent, crash of a transport never takes
  down the crypto runtime. Matches the existing binary-first precedent
  (`frame`, FileRelay). One process per enabled native transport (~11B
  framing overhead); WASM transports run in-process with no syscalls.

## 3. Trust model

Transports are **untrusted**, like the network:

- Core owns identity, sessions, ratcheting, encrypt/decrypt. It hands the
  transport only **opaque frames** (`[type byte][nanopack payload]`,
  `internal/frame`) plus routing hints (recipient pub bytes).
- The RPC API shape **cannot express private keys**: there is no field for
  them in any schema (§5). A malicious transport cannot request what the
  API cannot encode.
- FileRelay bridge uses the **courier model** (§7): it owns its own
  throwaway ed25519 courier keypair for shard rate-limit identity. Outer
  sender binding = courier; true sender lives inside the E2E-encrypted
  `SecureMessage`. The bridge never sees user keys — only opaque frames,
  recipient pubkeys, per-mailbox `read_secret` bearers (scoped, revocable
  by re-register), and URLs.
- Installs are **disabled by default**; `enable` is explicit. Package hash
  pinned at install, re-verified on every start and on update.
- `api_version` gate: core `1` ⇔ transport `1`, else refuse to start.

## 4. On-disk layout

```text
$NEXTALK_TRANSPORTS_DIR (else <user-config>/nextalk/transports)/
  <id>/
    manifest.json
    <entry binary>
    courier.key          # created by the transport itself, never read by core
  state.json             # { "enabled": {id: bool}, "hash": {id: sha256hex } }
```

`*.ntx` = zip with `manifest.json` at root + entry binary. No rebuild.

## 5. Transport API (v1, `api_version: 1`)

Stdio framing: `[len BE32][NanoPack body]`; body schema 100 =
`Envelope{op u8, req_id u32 BE, payload bytes}`. `req_id` matches
responses. stderr = logs only. Any op may answer with op 0 + SchemaError
instead of its typed response. Ops:

| op | req payload | res payload |
|---|---|---|
| 1 initialize | 101 Initialize{transport_id, api_version u8, config bytes} | 102 InitializeResult{ok, detail, actual_api} |
| 2 start/stop | 114 StartStop{action u8: 1/2} | 104 Ack{ok, detail} |
| 3 send | 103 Send{frame bytes, recipient_pub (0/32B), sender_hint (0/32B, logging only), mailbox_id (0/16B explicit address), shard_url} | 104 Ack |
| 4 attach | 105 Attach{mailbox_id 16B, read_secret 32B, shard_url, router_url} | 104 Ack |
| 5 detach | 106 Detach{mailbox_id 16B} | 104 Ack |
| 6 poll | 107 Poll{limit u8, mailbox_id (0/16B, empty=all)} | 108 PollResult{frames (BE32 len + bytes each), count u32} |
| 7 status | 109 empty `[0x00]` | 110 Status{running u8, detail} |
| 8 capabilities | 111 empty | 112 Caps{caps (u16len+bytes each), transport_id, version} |
| 9 register | 123 Register{user_tag, router_url} | 124 RegisterResult{mailbox_id, read_secret, shard_url, router_url} |
| 10 resolve | 125 Resolve{recipient_pub 32B, router_url} | 126 ResolveResult{mailbox_id, shard_url} |
| 11 xfer-create | 115 XferCreate{total u64, chunk_size/count u32, manifest ≤4KiB, mailbox (0/16B), recipient_pub (0/32B), shard_url} | 116 XferCreated{transfer_id, expires} |
| 12 xfer-put | 117 XferPut{transfer_id, index u32, payload ≤64KiB, hash 32B, offset u64} | 118 XferProgress{highest/count u32, ranges, bitmap, encoding} |
| 13 xfer-resume | 119 XferResume{transfer_id, mailbox_id, read_secret} | 118 XferProgress |
| 14 xfer-get | 120 XferGet{transfer_id, index u32, mailbox_id, read_secret} | 121 XferChunk{payload, hash} |
| 15 xfer-complete | 122 XferComplete{transfer_id, manifest_hash 32B} | 104 Ack |

Schema IDs **100–126**: no collision with NexTalk (`1,10,11,20,21,40,41,44`)
or FileRelay (`50–77`). Core interfaces: `FrameTransport`
(`SendFrame/PollFrames/Attach/Detach/Status/Capabilities/Start/Stop`) and
`FileTransport` (xfer + register/resolve, capability-gated via
`RequiresFile`/`FileRoute`).

Addressing (`RouteHint`): `send`/`xfer-create` carry **either** a recipient
pubkey **or** an explicit `(mailbox_id, shard_url)` address. Deterministic
transports (relay-example: mailbox = `sha256(pub)[:16]`) route by pubkey;
address-shared transports (filerelay: scoped-credential mailboxes are
unguessable from the peer key) require the explicit address the recipient
shared out-of-band. The built-in worker transport still serves
NexTalk-Relay; external transports never implement `relay.Relay` (that
interface takes private keys by design) — they serve polled frames into
`internal/dispatch`, the same path `worker listen` uses since the
dispatch migration.

## 6. Manifest (`manifest.json`)

```json
{
  "id": "filerelay",
  "name": "FileRelay",
  "version": "1.0.0",
  "api_version": "1",
  "entry": "filerelay-bridge",
  "capabilities": ["message", "binary-transfer"],
  "permissions": ["network", "storage"],
  "description": "..."
}
```

Known capabilities: `message`, `binary-transfer`, `presence`,
`local-network`, `p2p`. Known permissions: `network`, `storage`.
Unknown capability/permission ⇒ install refused (fail closed).
`signing_domains` intentionally absent in v1 (courier model needs none).

## 7. FileRelay integration (first external transport, courier model)

```text
NexTalk Core (keys, encrypt, frame) --FrameTransport RPC--> filerelay-bridge
  (own courier key, router resolve, pre-signed FileRelay bodies) --> shard/router
```

- Bridge lives in `NexTalk-FileRelay/transports/filerelay/` (manifest +
  Go bridge). Zero FileRelay storage/router code enters NexTalk core.
- Capabilities: `message` + `binary-transfer`, both live: files are E2E
  encrypted whole-file by `internal/filetransfer`, chunked opaquely, and
  driven through the `FileTransport` xfer ops (see `docs/real-scenario.md`).
- Core passes per-call: opaque frame, recipient pub, mailbox bearers, URLs.
  Never keys. Shard sees courier sender binding + opaque envelopes;
  burn-after-read, TTL, quotas unchanged server-side.

## 7.1 Unified relay model (one relay for messages, another for files)

Message relays and file relays are not separate concepts — both are
`FrameTransport`/`FileTransport` capability providers behind one manager,
and a transfer is referenced from a message by a **ticket**:

```text
Alice's file relay (her mailbox)          any message relay
  upload → transfer_id + download ticket
                                          ticket (base64 NanoPack) inside an E2E message ──▶ Bob
Bob's FileRelay view: ticket + shard ──▶ resume/get (no mailbox, no session)
```

- Upload to your own relay space; share the ticket — NanoPack schema 13
  (`filetransfer.Ticket`: version, transfer_id, download secret, shard,
  embedded schema-12 manifest, sender; raw bytes throughout), carried as one
  base64 string inside a message — or a dedicated ticket-only message whose
  sole purpose is negotiation. JSON is display-only here
  (`Ticket.Describe`, CLI stderr); it never travels.
- The recipient fetches with the ticket alone. Capability routing stays
  generic: `Route("message")` / `FileRoute()` pick any installed transport
  declaring the capability, present or future (`presence`, `p2p`, …).
- Lifecycle: upload → ticket minted at create → secret travels in NexTalk
  messages → retrieval by ticket → expiry/cancel kills the ticket. The relay
  never sees message content or private keys at any step.

## 8. CLI

```text
nextalk transport list
nextalk transport install <file.ntx> [--enable]
nextalk transport remove <id>
nextalk transport enable <id>
nextalk transport disable <id>
nextalk transport status [<id>]
nextalk transport attach <id> --mailbox <hex> --secret <hex> --shard <url> [--router <url>]
nextalk transport detach <id> --mailbox <hex>
nextalk transport poll <id> -i <peer> [--mailbox <hex>] [--limit N] [--format json]
nextalk transport send-frame <id> [--to <peer|pub> | --mailbox <hex> --shard <url>] -f frame.bin
nextalk transport register <id> -i <peer> [--router <url>]   # tag derived internally; auto-attaches
nextalk transport resolve <id> --to <peer|pub> --router <url>
nextalk transport xfer-send <id> -i <peer> --to <peer> [--mailbox <hex> --shard <url>] -f file [--chunk-size N]
nextalk transport xfer-recv <id> -i <peer> --from <peer> (--ticket <base64> | --transfer <hex> --mailbox <hex> --secret <hex> --manifest <b64>) -o out
```

## 9. Security properties

- No privkey field exists in the RPC; code-reviewed by construction.
- Per-mailbox bearers scoped to delivery; revocable via re-register.
- Hash pinning (install/update/start), `api_version` gate, disabled default.
- Timeouts on every RPC; kill + quarantine (auto-disable) on crash/timeout.
- Rate limits stay server-side (shard) — courier key is rate-limited as one sender.
- Signing/permission `identity-keys` does not exist and must never be added
  without a design amendment.
- WASM modules run under wazero with no WASI, no sockets, no filesystem —
  only linear memory and an optional `ntx.log` import.

## 10. WASM transports

`.ntx` packages whose manifest `entry` ends in `.wasm` run in-process under
wazero instead of spawning. The function-call ABI (see `internal/transport/wasm.go`
header) passes blobs as `(ptr,len)` pairs; data returns pack `(ptr<<32|len)`
u64; the core copies results out immediately so modules may reuse static
out-regions. v1 fits queue-model `message` transports; socket-needing
transports use the process model. `TestWASMInstallToRun` proves
package → install → run → send/poll with a hand-assembled module (the
assembler in `wasm_*_test.go` doubles as the ABI reference implementation).

## 11. Roadmap (remaining)

- FileRelay `binary-transfer` over WASM (ABI has room; needs socket-capable
  WASI story — deliberately out of v1).
- Optional transport signing keys (upgrade from hash-pinning to signatures).
- `send-multi` fan-out over external transports (receive path is done;
  sending needs a Relay-compatible fan-out sender).
