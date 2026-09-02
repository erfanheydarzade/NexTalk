# NexTalk Framing Standard

Every transport — worker (Cloudflare relay), offline (copy/paste), proxy
(S3 relay), and the wasm/browser bridge — moves the same payloads over
different media. This document defines the ONE framing standard they all
share, who owns each layer, and what every transport must implement to be
"full".

## Layer 0 — payload bodies (nanopack)

Payloads are always [nanopack](https://github.com/erfanheydarzade/nanopack)
binary bodies: 1-byte field IDs, varint lengths, no reflection. The registry
lives in [serialization.md](serialization.md).

## Layer 1 — the frame

```
[type byte][payload bytes]
```

| Type   | Name       | Payload                                        |
|--------|------------|------------------------------------------------|
| `0x01` | `offer`    | `core.HandShakeOffer`                          |
| `0x02` | `answer`   | `core.HandShakeAnswer`                         |
| `0x03` | `message`  | `crypto.SecureMessage` (encrypted DM)          |
| `0x04` | `multimsg` | ratchet-encrypted group delivery (see groups.md) |

Owned by **`internal/frame`** (`Wrap`, `Unwrap`, `Type`). Transports never
hand-roll this byte; anything that sends via `relay.Relay.Send` already does.

## Layer 2 — transfer containers

Wherever a *human* moves bytes (air-gap paste, QR codes, files), frames travel
inside a small JSON container:

```json
{ "Type": "multimsg", "Data": "<base64 of the FULL frame>" }
```

- `Data` carries base64 of the complete layer-1 frame **including its type
  byte**, so a container is self-describing even stripped of its Type field.
- Decoding accepts two historical shapes for compatibility:
  - current: `Data` = base64(full frame);
  - legacy:  `Data` = base64(bare payload), `Type` names the kind;
  - plus raw frames with no JSON at all.
- A container whose `Type` field disagrees with its frame byte is rejected,
  not guessed.

Owned by **`internal/frame`** (`Container`, `EncodeContainer`,
`DecodeContainer`).

## Layer 3 — the group-chat surface

Multi-message support is one shared implementation, not per-transport code:

| Concern | Owner |
|---|---|
| Shell commands (`context`, `send-multi`, `contexts`, `mailbox`) | `internal/groupchat.Specs()` + `.Execute()` |
| CLI commands (same four, cobra) | `internal/groupchat.ContextCLI / SendMultiCLI / ContextsCLI / MailboxCLI` |
| Context/policy/delivery persistence | `internal/multimsg.FileContextStore / FileDeliveryStore` (`<id>.*.np`) |
| Conversation history | `internal/mailbox.Store` (`<id>.mailbox.np`) |
| Inbound classification & recording | `internal/groupchat.Ingest` |

### Transport capability matrix

A transport is **full** when it implements all three rows.

| Capability | Worker | Offline | Proxy | WASM |
|---|---|---|---|---|
| Manage contexts (create/add/policies/rename) | ✅ | ✅ | ✅ | ✅ (`NexTalk.context.*`) |
| send-multi | transmits via relay | exports Containers | exports Containers | `context.sendMulti` |
| Receive group deliveries | `listen` (0x04 auto-dispatch) | `decrypt` → `groupchat.Ingest` | `decrypt` → `Ingest` | `relay.listen()` events |

Relay-less transports (offline, proxy-until-its-adapter-exists) do NOT lose
functionality: `send-multi` still encrypts one copy per recipient through the
established 1:1 sessions and emits each copy as a layer-2 Container addressed
to its recipient ("DELIVER TO <peer>"). The recipient runs it through
`decrypt`/Ingest; the message lands in the same group thread, with the
creator-signed group name learned from the wire, deduplicated by message ID —
byte-for-byte the same path a relayed delivery takes after transmission.

## Rules for new transports

1. Frame everything with `internal/frame`; never invent a type byte.
2. Reuse `groupchat.Specs()/Execute()` in your shell and the CLI builders in
   your cobra registration — do not fork the surface.
3. Persist through `registry.State.InitFanout()` + `InitMailbox()` so history
   and groups survive restarts and interoperate with other transports.
4. If you cannot transmit, export Containers; if you receive bytes, run them
   through `groupchat.Ingest`.
