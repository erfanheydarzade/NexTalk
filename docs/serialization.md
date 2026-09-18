# Serialization Policy

NexTalk uses [nanopack](https://github.com/erfanheydarzade/nanopack) — a
compact, reflection-free binary serialization library — for every protocol
payload and every local data store. JSON survives only at deliberate
human/scripting boundaries. This document is the single source of truth for
what is serialized where, why, and how old formats migrate.

## Why nanopack over JSON

| | JSON | nanopack |
|---|---|---|
| Wire size per field | name string + text numbers | 1-byte field ID + varint length |
| Binary key material | base64-in-strings (+33%) | native `[]byte` |
| Decode fidelity | lossy by default (`[]byte` copies, float quirks) | exact bytes, aliasing documented |
| Tamper detection | none | CRC16 envelope (`WrapPacket`) |
| Reflection on hot path | yes | none |

## Where each format lives

### nanopack (wire)

| Payload | Schema ID | Notes |
|---|---|---|
| `crypto.SecureMessage` (encrypted DM frame) | — (raw body) | inside relay type `0x03` |
| `multimsg.MessageContext` descriptor | — (embedded) | carried inside group deliveries |
| `core.HandShakeOffer` | 20 | relay type `0x01` |
| `core.HandShakeAnswer` | 21 | relay type `0x02` |
| `filetransfer.Manifest` (encrypted-file descriptor) | 12 | embedded in transfer tickets; opaque blob to the relay |
| `filetransfer.Ticket` (transfer reference) | 13 | message content (base64 at copy-paste boundary) |

Legacy compatibility: receivers accept pre-nanopack **JSON** handshake
payloads from older builds — any payload whose first byte is `{` is parsed as
JSON; everything else as nanopack. We only ever *send* nanopack.

The group fan-out wrapped payload (inside each delivery's ciphertext) has its
own versioned layout — see [groups.md](groups.md), "Wire Format".

### nanopack (local stores, via `internal/binstore`)

Store files are CRC-framed record lists: one nanopack envelope whose body is
`uvarint(count) || (uvarint(len) || record)*`.

| Store | File | Record schema ID | Record struct |
|---|---|---|---|
| Contacts book | `contacts.np` | 40 | `contacts.contactBin` |
| Mailbox messages | `<id>.mailbox.np` | 41 | `mailbox.messageBin` |
| Contexts | `<id>.contexts.np` | 10 | `multimsg.MessageContext` |
| Deliveries | `<id>.deliveries.np` | 11 | `multimsg.MessageDelivery` |
| Recipient policies | `<id>.policies.np` | 44 | `multimsg.policyBin` |

Schema IDs are permanent once shipped (nanopack wire-compatibility rule).
Renumbering anything in this table is a breaking protocol change.

### JSON (deliberate boundaries)

JSON remains exactly where machines talk to humans or browsers:

1. **CLI scripting output** — every command's `--format json`. This is an
   interface contract consumed by scripts (`test.py`, CI); it never travels
   over the wire.
2. **Offline paste envelopes** — `{Type, Data}` where `Data` is base64 of the
   nanopack payload. This boundary exists for humans pasting across air gaps;
   base64-in-JSON survives terminals and QR encoders.
3. **Identity files** — `<id>.json` holds keys + ratchet session state.
   Kept as JSON deliberately: `SecurePeer` nests maps of skipped message keys
   that have no nanopack schema, and hand-inspectability of key material is a
   recovery feature, not an accident.
4. **Browser bridge** — `wasmbridge` marshals JS-facing results through JSON
   objects; that is the Go↔JS boundary, not a storage or wire format.
5. **Relay server HTTP APIs** — the Cloudflare router/shard endpoints accept
   and return JSON bodies; that contract belongs to the server.

## Migration policy

- New-format stores are written exclusively; legacy formats are **read once**
  and transparently re-persisted in place as `.np`.
- Legacy files are **never deleted automatically** — they stay on disk as
  user-owned backups until removed manually.
- A corrupt `.np` file is an error, not silent data loss; corrupted
  *individual records* are skipped so one bad row cannot fail a whole load.
