# NexTalk

[![CI](https://github.com/erfanheydarzade/NexTalk/actions/workflows/ci.yml/badge.svg)](https://github.com/erfanheydarzade/NexTalk/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/erfanheydarzade/NexTalk)](https://github.com/erfanheydarzade/NexTalk/releases)

> A hybrid post-quantum cryptographic messaging protocol runtime, written in Go.

NexTalk is **not** a chat application. It is a research-grade **cryptographic execution engine** — a protocol runtime that handles end-to-end encrypted messaging over multiple untrusted transport backends. The focus is architectural: clean separation between cryptography, protocol logic, and transport uncertainty.

---

## What NexTalk Actually Does

NexTalk establishes a secure, forward-secret session between two peers using a hybrid classical + post-quantum key exchange, then exchanges encrypted messages over one of several pluggable transport backends (Cloudflare Workers KV, S3-compatible object storage, or fully offline copy-paste).

---

## Architecture

```
cmd/
  contacts/        → Global contacts management (add, remove, rename, note, info, list)
  nextalk/          → Binary entry point (main.go)
  nextalk-wasm/     → WebAssembly build target (main.go + build.sh/build.bat)
  offline/          → Cobra subcommands: init, offer, accept, finish, encrypt, decrypt, run
  worker/           → Worker transport subcommand + registration
  proxy/            → Proxy transport subcommand + registration
  shell/              → shell launcher
  transports/       → Transport auto-registration via side-effect imports
  
core/               → Protocol engine: handshake orchestration, session management
crypto/             → Cryptographic primitives: keys, ratchet, AEAD, HKDF
client/             → Peer identity state + persistent session storage (JSON files)

transport/          → Raw relay adapters: Cloudflare KV (worker.go), S3 (proxy.go)

internal/
  codec/            → Input/output encoding helpers (raw, b64, hex)
  config/           → Environment config loader (.env)
  contacts/         → Global contact store
  registry/         → Transport registry
  relay/            → Transport adapter interfaces
    worker/         → Cloudflare Worker adapter
    proxy/          → S3/proxy adapter
  session/          → Session state helpers
  wasmbridge/       → JS <-> Go bridge powering the browser build (one file per concern)

web/                → Browser demo (index.html) that loads the wasm bundle
```

Each layer has a well-defined trust boundary:

| Layer       | Trust Level                                              |
|-------------|----------------------------------------------------------|
| `crypto`    | Fully trusted — all cryptographic primitives             |
| `core`      | Fully trusted — owns protocol correctness                |
| `client`    | Trusted — manages local identity and session state       |
| `transport` | **Untrusted** — treats all relay infrastructure as hostile |
| `cmd`       | Orchestration only — no cryptographic decisions          |

The transport layer never sees plaintext. It only routes opaque, already-encrypted
bytes — how those bytes are framed (JSON vs. a raw type-byte prefix) differs
per transport; see [Wire Formats](#wire-formats) below.

---

## Cryptographic Design

### Identity

Each peer has a long-term identity composed of:

- **Ed25519** keypair — classical signing, used for handshake signature verification
- **Dilithium3 (ML-DSA)** keypair — post-quantum signing (CIRCL mode3)
- Canonical **Peer ID** = `base58( Ed25519Public ‖ SHA3-256(DilithiumPublic) )`

The Peer ID is stable across sessions and encodes both classical and post-quantum identity material.

### Key Exchange (Per Session)

Each session generates fresh ephemeral key material:

- **X25519** — classical ECDH
- **Kyber768** — post-quantum KEM (CRYSTALS-Kyber, NIST Level 3)

Hybrid shared secret: `X25519_shared ‖ Kyber_shared_secret`

Breaking either primitive independently is insufficient to compromise the session.

### Key Derivation

Session keys are derived from the hybrid shared secret via **HKDF-SHA256**, bound to a transcript:

```
transcript = SHA3-512("ML-KEM-ECC-Hybrid-Transcript-v1" ‖ sorted_hash(all pubkeys))
root_key   = HKDF(hybrid_shared_secret, transcript, "initial-root")
```

The transcript sorts all public key hashes before combining them — making it **order-independent**. Both peers derive the same binding regardless of message timing.

From the root key, an initial DH ratchet step produces:

```
[SendCk | RecvCk | RootKey | HmacKey | FileKey] = HKDF(DH_shared, root_key, "ratchet-root")
```

Initiator/responder roles are assigned deterministically by comparing SHA-256 hashes of identity keys.

### Message Encryption

Each message is encrypted with **XChaCha20-Poly1305**:

- Message key derived from the send chain via a symmetric ratchet step
- Nonce = 24-byte message counter
- AAD = `DH_ratchet_public ‖ message_nonce`
- Integrity protected with **HMAC-SHA3-256** over the full serialized message

### Double Ratchet

- **Symmetric ratchet** — each message advances the chain key, producing a fresh one-time message key
- **DH ratchet** — triggered when a new remote DH public key is received; updates root key and receive chain
- **Skipped message keys** — stored for out-of-order delivery, bounded by `maxSkip = 1000`
- **Replay protection** — messages with nonces below the current receive counter are hard-rejected

---

## Wire Formats

Handshake payloads (offer/answer) are JSON `core.HandShakeOffer`/`HandShakeAnswer`
structs; encrypted message frames are always binary
[nanopack](https://github.com/erfanheydarzade/nanopack) `crypto.SecureMessage`
payloads. How those payloads get framed for transport differs per backend —
see below.

### Transport envelopes

There is no single wire envelope shared by every transport — each one frames
the same three payload kinds (offer / answer / message) differently. `finish`
is never one of them: it's a local action name for processing a received
*answer*, not something that travels on the wire.

- **Offline mode** (copy/paste) — JSON, but the `Envelope{Type, Data}` struct
  carries no `json:` tags, so the real keys are capitalized and `Data` is a
  base64 **string**, not a nested object:
  ```json
  { "Type": "offer", "Data": "base64..." }
  ```
  (`cmd/offline/models.go`)

- **Worker transport** (Cloudflare relay) — not JSON at all: a single raw
  type byte prefixed onto the payload, `0x01`/`0x02`/`0x03` for
  offer/answer/message:
  ```
  [type byte][raw payload bytes]
  ```
  built by `relay.WrapEnvelope` / read back by `relay.worker.UnwrapEnvelope`,
  and shared by the CLI's `worker` transport and the wasm bridge.

- **Proxy transport** — JSON with a numeric `type` (1/2/3) and `data` as a
  real embedded JSON object:
  ```json
  { "type": 1, "data": { ... } }
  ```
  (`internal/relay/proxy/adapter.go`)

In every case the transport layer only routes opaque bytes — it never
inspects the decoded offer/answer/message payload itself.

### Message frame (nanopack)

`crypto.SecureMessage` is tagged for nanopack code generation, so field *names*
never travel on the wire — only one-byte IDs, and the nonce as 8 raw big-endian
bytes rather than ASCII digits:

| ID | Field | Contents |
|----|-------|----------|
| 1 | `SenderID` | sender's peer ID |
| 2 | `RatchetKey` | sender's current ratchet DH public key |
| 3 | `Nonce` | message counter, `uint64` big-endian |
| 4 | `Ciphertext` | ChaCha20-Poly1305 ciphertext |
| 5 | `Tag` | HMAC-SHA3-256 over the canonical form of fields 1–4 |

Fields 1–4 are exactly what the HMAC authenticates, so the canonical payload is
just the generated `MarshalBinID` output with no re-marshalling tricks; the tag
is appended after it. Frames are sent without nanopack's `WrapPacket` envelope
(magic byte + CRC), since every transport here already frames reliably.

After changing the tags on `SecureMessage`, regenerate the marshal code:

```bash
go run github.com/erfanheydarzade/nanopack/cmd/bingen
```

That rewrites `crypto/kex_hybrid_nanopack.go` in place. Field IDs are the wire
contract — renumbering them breaks compatibility with already-deployed peers.

---

## Building

```bash
go build ./cmd/nextalk
# or
go build -o nextalk.exe ./cmd/nextalk
```

Requires Go 1.25+ (see `go.mod`). Dependencies are managed via `go.mod`.

### Prebuilt binaries

Prebuilt `nextalk` archives — Linux (amd64/arm64/armv7), macOS (amd64/arm64),
Windows (amd64 only) — and a ready-to-serve WebAssembly bundle are published
on the [Releases page](https://github.com/erfanheydarzade/NexTalk/releases)
for every tagged version — see [`docs/RELEASING.md`](docs/RELEASING.md) for
how those get built. For the browser build specifically, see
[`docs/wasm.md`](docs/wasm.md), including why it must be served over
HTTP (`python3 -m http.server`) rather than opened as a `file://` URL.

---

## CLI Usage — Offline Mode

Offline mode is a self-contained cryptographic lab with no networking. It is the reference implementation of the protocol and is used for testing, debugging, and manual session bootstrapping.

Each command outputs a JSON envelope to stdout by default. Blobs can also be written to files or piped between commands to complete a handshake.

All `--in` / `--out` flags accept `raw` (default), `b64`, or `hex`. The exception is `offline decrypt`, where `--in` defaults to `b64` since ciphertext almost always travels base64-encoded.

---

### `init` — Create a new peer identity

```bash
./nextalk offline init
./nextalk offline init --format json
```

Generates a fresh Ed25519 + Dilithium3 identity and persists it to `<peer_id>.json` in the working directory.

**Output (human, default)** — printed to stdout:
```
[✓] Identity created

ID:
3tJcNVmRHZ7CFhF1WPUDyECp...
```

**Output (`--format json`)** — the response structs across every offline
subcommand carry no `json:` struct tags, so keys are the bare capitalized Go
field names, not lower-camelCase:
```json
{"ID":"3tJcNVmRHZ7CFhF1WPUDyECp..."}
```

---

### `offer` — Generate a handshake offer (Initiator, Step 1)

```bash
./nextalk offline offer -i <local_peer_id> -r <remote_peer_id>            # raw bytes to stdout
./nextalk offline offer -i <local_peer_id> -r <remote_peer_id> -o offer.bin   # write to file
./nextalk offline offer -i <local_peer_id> -r <remote_peer_id> --out b64  # base64 to stdout
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Local peer ID (required) |
| `--remotePeer` | `-r` | Recipient peer ID (required) |
| `--output` | `-o` | Write offer blob to file (raw bytes); disables stdout |
| `--out` | | stdout encoding: `raw`, `b64`, `hex` — ignored when `-o` is used (default: raw) |
| `--format` | | `human` or `json` |

Loads `<local_peer_id>.json`, generates ephemeral keys + Kyber768 keypair, signs the bundle with Ed25519 + Dilithium3, and outputs an offer envelope.

**Output (no `-o`, default `--out raw`)** — the envelope itself written straight
to stdout: `json.Marshal(Envelope{Type: "offer", Data: offerBytes})`, where
`Envelope` has no `json:` tags (capitalized keys) and `Data` is the raw offer
bytes, base64-encoded by `encoding/json`'s `[]byte` handling:
```json
{"Type":"offer","Data":"<base64 of the core.HandShakeOffer JSON>"}
```

**Output (`--format json`)** — wraps that same encoded envelope string in an
`OfferResponse`, again untagged:
```json
{"RemotePeer":"<remote_peer_id>","Envelope":"<encoded envelope string>","Encoding":"raw"}
```

`core.HandShakeOffer` (the struct actually inside `Data`) uses full
lower-camelCase field names, not abbreviations:
`senderId`, `recipientId`, `offerID`, `idPub`, `pub`, `dhPub`, `kyberPub`,
`dilithiumPub`, `sign`, `dilithiumSign` (see `core/models.go`).

---

### `accept` — Accept an offer and generate an answer (Responder, Step 2)

```bash
./nextalk offline accept -i <local_peer_id> -f offer.bin -o answer.bin        # file in → file out
./nextalk offline accept -i <local_peer_id> -e <B64_OFFER> --in b64 --out b64 # inline b64 round-trip
cat offer.bin | ./nextalk offline accept -i <local_peer_id> -o answer.bin     # piped stdin
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Local peer ID (required) |
| `--offerEnvelope` | `-e` | Inline offer blob |
| `--file` | `-f` | File containing the offer |
| `--output` | `-o` | Write answer blob to file |
| `--in` | | Input encoding: `raw`, `b64`, `hex` (default: raw) |
| `--out` | | stdout encoding (default: raw) |
| `--format` | | `human` or `json` |

Offer can also be piped via stdin (omit `-e` and `-f`). Verifies both signatures (Ed25519 + Dilithium3), checks Offer ID for replay, **encapsulates** the initiator's Kyber768 public key to produce `(kyber_ciphertext, shared_secret)`, runs the full handshake, and outputs an answer envelope.

**Output (no `-o`, default `--out raw`)** — same untagged `Envelope` shape as
`offer`, type `"answer"`:
```json
{"Type":"answer","Data":"<base64 of the core.HandShakeAnswer JSON>"}
```

**Output (`--format json`)** wraps it in an `AcceptResponse{Envelope, Encoding}`:
```json
{"Envelope":"<encoded envelope string>","Encoding":"raw"}
```

`core.HandShakeAnswer` mirrors `HandShakeOffer` plus `kyberCiphertext`:
`senderId`, `recipientId`, `offerID`, `idPub`, `pub`, `dhPub`, `kyberPub`,
`kyberCiphertext`, `dilithiumPub`, `sign`, `dilithiumSign`.

---

### `finish` — Finalize the session (Initiator, Step 3)

```bash
./nextalk offline finish -i <local_peer_id> -f answer.bin           # from file
./nextalk offline finish -i <local_peer_id> -a <B64_ANSWER> --in b64  # inline base64
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Local peer ID (required) |
| `--answerEnvelope` | `-a` | Inline answer blob |
| `--file` | `-f` | File containing the answer |
| `--in` | | Input encoding: `raw`, `b64`, `hex` (default: raw) |
| `--format` | | `human` or `json` |

**Decapsulates** the Kyber ciphertext using the initiator's stored private key to recover `shared_secret`, then runs the same handshake derivation. If both peers derived the same shared secret, their session keys will match and the ratchet is active.

**Output (human, default)** — printed to **stderr** (stdout stays clean for
piping):
```
[✓] Session established

Peer:
<remote_peer_id>
```

**Output (`--format json`)** — `FinishResponse{PeerID string}`, untagged:
```json
{"PeerID":"<remote_peer_id>"}
```

There is no `finish` wire type — nothing is sent anywhere by this command; it
only updates local session state from the answer already received.

---

### `encrypt` — Encrypt a message

```bash
./nextalk offline encrypt -i <local_peer_id> -r <remote_peer_id> -m "hello"           # inline message
./nextalk offline encrypt -i <local_peer_id> -r <remote_peer_id> -f secret.txt -o cipher.bin  # file in → file out
echo "hello" | ./nextalk offline encrypt -i <local_peer_id> -r <remote_peer_id> --out b64     # stdin → b64 stdout
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Local peer ID (required) |
| `--remotePeer` | `-r` | Target session peer ID (required) |
| `--message` | `-m` | Inline plaintext |
| `--file` | `-f` | Plaintext input file |
| `--output` | `-o` | Write ciphertext to file |
| `--in` | | Input encoding: `raw`, `b64`, `hex` (default: raw) |
| `--out` | | stdout encoding: `raw`, `b64`, `hex` (default: raw) |
| `--format` | | `human` or `json` |

If neither `--message` nor `--file` is given, plaintext is read from stdin. Binary output to a TTY requires `--out b64`/`--out hex` or `-o file`. Loads the active session for the remote peer, advances the send ratchet, and outputs the raw `crypto.SecureMessage` nanopack frame — **not** a JSON envelope like `offer`/`accept`.

**Output (no `-o`, `--format json`)** — reuses the same `DecryptResponse`
struct as the `decrypt` command (see `cmd/offline/encrypt.go`), untagged:
```json
{"Sender":"<remote_peer_id>","Encoding":"b64","Message":"<base64 SecureMessage frame>"}
```

**Output (no `-o`, human, `--out b64`/`--out hex`)** — the encoded frame
printed directly to stdout with no JSON wrapper at all; `--out raw` to a TTY
is refused with an error telling you to use `-o` or `--out b64`/`hex` instead.

---

### `decrypt` — Decrypt a message

```bash
./nextalk offline decrypt -i <local_peer_id> -f cipher.bin              # from file (raw input)
./nextalk offline decrypt -i <local_peer_id> -c <B64_CIPHER> --in b64   # inline base64
./nextalk offline decrypt -i <local_peer_id> -f cipher.bin -o plain.txt # save decrypted to file
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Local peer ID (required) |
| `--cipherText` | `-c` | Inline ciphertext blob |
| `--file` | `-f` | Encrypted input file |
| `--output` | `-o` | Write decrypted content to file |
| `--in` | | Input encoding: `raw`, `b64`, `hex` (default: **b64**) |
| `--out` | | stdout encoding (default: raw) |
| `--format` | | `human` or `json` |

Note: `--in` defaults to `b64` here (unlike all other commands) since ciphertext almost always arrives base64-encoded in transit. Binary output to a TTY requires `--out b64`/`--out hex` or `-o file`. Verifies HMAC, resolves the sender session, handles any DH ratchet advancement, and decrypts.

**Output (human, default)** — status to **stderr**, plaintext alone to
**stdout** (only when it decodes as text; binary content without `-o` is
refused to protect the terminal):
```
[✓] Message decrypted

From:
<sender_peer_id>

```
```
hello world
```

**Output (`--format json`)** — `DecryptResponse{Sender, Encoding, Message}`,
untagged; `Encoding` is `"utf-8"` for text or `"base64"` for binary payloads:
```json
{"Sender":"<sender_peer_id>","Encoding":"utf-8","Message":"hello world"}
```

---

### `run` — Start the interactive offline REPL

```bash
./nextalk offline run
```

Launches the interactive offline shell with the same commands available as one-liners: `init`, `load`, `offer`, `accept`, `finish`, `encrypt`, `decrypt`, `exit`.

---

## Full Offline Handshake Example

### Inline / piped (scripted)

```bash
# Step 0: create identities for Alice and Bob
ALICE=$(./nextalk offline init | jq -r '.id')
BOB=$(./nextalk offline init | jq -r '.id')

# Step 1: Alice creates an offer (base64 stdout for safe transport)
OFFER=$(./nextalk offline offer -i "$ALICE" -r "$BOB" --out b64)

# Step 2: Bob accepts the offer and produces an answer
ANSWER=$(./nextalk offline accept -i "$BOB" -e "$OFFER" --in b64 --out b64)

# Step 3: Alice finalises the handshake
./nextalk offline finish -i "$ALICE" -a "$ANSWER" --in b64

# Step 4: Alice sends an encrypted message to Bob
CIPHER=$(./nextalk offline encrypt -i "$ALICE" -r "$BOB" -m "hello world" --out b64)

# Step 5: Bob decrypts it
./nextalk offline decrypt -i "$BOB" -c "$CIPHER" --in b64
# stderr: [✓] Message decrypted / From: <alice_id>
# stdout: hello world

# Same thing, machine-readable:
./nextalk offline decrypt -i "$BOB" -c "$CIPHER" --in b64 --format json
# → {"Sender":"<alice_id>","Encoding":"utf-8","Message":"hello world"}
```

### File-based (air-gap / manual exchange)

```bash
ALICE=$(./nextalk offline init | jq -r '.id')
BOB=$(./nextalk offline init | jq -r '.id')

# Alice writes the offer to disk and hands the file to Bob out-of-band
./nextalk offline offer  -i "$ALICE" -r "$BOB" -o offer.bin

# Bob accepts and writes the answer to disk
./nextalk offline accept -i "$BOB" -f offer.bin -o answer.bin

# Alice finalises
./nextalk offline finish -i "$ALICE" -f answer.bin

# Alice encrypts a file for Bob
./nextalk offline encrypt -i "$ALICE" -r "$BOB" -f secret.txt -o cipher.bin

# Bob decrypts it
./nextalk offline decrypt -i "$BOB" -f cipher.bin -o plain.txt
```

---

## CLI Usage — Contacts

The global address book is independent of any identity or transport. Contacts map friendly names to raw peer IDs, so you can pass `alice` anywhere a peer ID is expected.

Mutation commands (`add`, `remove`, `rename`, `note`) emit JSON confirmation. Read commands (`info`, `list`) print structured output.

### `contacts add`

```bash
nextalk contacts add <name> <peer_id>
nextalk contacts add alice 5Ht3...
```

### `contacts remove`

Aliases: `rm`, `delete`.

```bash
nextalk contacts remove alice
nextalk contacts rm alice
```

### `contacts rename`

```bash
nextalk contacts rename alice ali
```

### `contacts note`

Attach or update a free-text note on a contact. Pass an empty string to clear.

```bash
nextalk contacts note alice "met at conf 2025"
nextalk contacts note alice ""
```

### `contacts info`

Print a single contact's name, peer ID, and note as JSON.

```bash
nextalk contacts info alice
```

### `contacts list`

Alias: `ls`. Prints a human-readable table and the underlying JSON.

```bash
nextalk contacts list
nextalk contacts ls
```

---

## CLI Usage — Worker Mode

Worker mode routes all traffic through a Cloudflare Workers relay (`WORKER_URL`). All subcommands accept `--format human` (default) or `--format json` for scripting.

### `worker init`

Generate a fresh Ed25519 identity, persist it locally, and register its mailbox with the relay. Prints the new peer ID.

```bash
nextalk worker init
nextalk worker init --format json
```

### `worker connect`

Send a post-quantum handshake offer to a remote peer via the relay.

```bash
nextalk worker connect -i <YOUR_ID> -r <PEER_ID>
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Your local peer ID (required) |
| `--remotePeer` | `-r` | Recipient peer ID (required) |
| `--format` | | `human` or `json` (default: human) |

### `worker listen`

Poll the relay inbox and process all pending events: automatically answers incoming handshake offers and delivers decrypted messages.

```bash
nextalk worker listen -i <YOUR_ID>
nextalk worker listen -i <YOUR_ID> --format json
```

Top-level event `type` values: `offer`, `answer`, `message`, `error`. `offer`
and `answer` events also carry an `actions` array recording what `listen` did
automatically in response — `answer_sent` after auto-accepting an offer,
`session_established` after auto-finishing on a received answer.

### `worker encrypt`

Encrypt a message or file and dispatch it to a peer through the relay. Requires an established session (`connect` + `listen` first).

```bash
nextalk worker encrypt -i <YOUR_ID> -r <PEER_ID> -m "hello"
nextalk worker encrypt -i <YOUR_ID> -r <PEER_ID> -f plaintext.txt
nextalk worker encrypt -i <YOUR_ID> -r <PEER_ID> -m "hello" --out hex
```

| Flag | Short | Description |
|------|-------|-------------|
| `--id` | `-i` | Your local peer ID (required) |
| `--remotePeer` | `-r` | Recipient peer ID (required) |
| `--message` | `-m` | Inline plaintext |
| `--file` | `-f` | Path to plaintext input file |
| `--in` | | Input encoding: `raw`, `b64`, `hex` (default: raw) |
| `--out` | | Output encoding for the echoed ciphertext: `raw`, `b64`, `hex` (default: b64) |
| `--format` | | `human` or `json` |

If neither `--message` nor `--file` is given, plaintext is read from stdin.

### Scripted worker handshake

```bash
ALICE=$(nextalk worker init --format json | jq -r .id)
BOB=$(nextalk worker init --format json | jq -r .id)

nextalk worker connect -i "$ALICE" -r "$BOB"
nextalk worker listen  -i "$BOB"              # auto-answers offer
nextalk worker listen  -i "$ALICE"            # finalises session
nextalk worker encrypt -i "$ALICE" -r "$BOB" -m "hello"
nextalk worker listen  -i "$BOB" --format json
```

---

## CLI Usage — Shell Mode

```bash
./nextalk shell
```

Launches the full shell transport selector:

```
╔════════════════════════════════════════╗
║               NexTalk CLI              ║
╚════════════════════════════════════════╝

  1. Offline Mode  (Manual Cryptography Lab)
  2. Worker Mode   (Cloud Relay)
  3. 3. Proxy Mode    (Anonymized Routing)
  4. Exit
```

(The doubled `3.` on the Proxy line isn't a typo here — `ProxyGUITransport.MenuLabel()`
bakes its own `"3. "` prefix into the string in `cmd/proxy/register.go`, on top of
the index the shell's menu loop already prints.)

After selecting a transport, you enter a persistent shell:

```
╭─[nextalk:worker]
╰─❯
```

### Worker Mode Commands

| Command | Description |
|---------|-------------|
| `init` | Generate a new identity and register with the Cloudflare relay |
| `load <id>` | Load an existing identity and re-register |
| `connect <peer_id>` | Send a handshake offer to a peer via the relay |
| `listen` | Poll the relay inbox and automatically process offers/answers/messages |
| `send <peer_id> <msg>` | Encrypt a message and dispatch it to the relay |
| `mailbox` | List all active peer chats with unread indicators |
| `mailbox <peer_id>` | Read messages from a specific peer (marks as read) |
| `peers` | List every peer ID the shell can Tab-complete |
| `switch` / `exit` | Return to the main transport selector |

The `listen` command handles the full handshake automatically:
- Incoming **offer** → auto-accept and send answer
- Incoming **answer** → auto-finish and activate session
- Incoming **message** → decrypt and store in mailbox

---

## Shell Tab Completion

Peer IDs are 44-character base58 strings, so the shell completes them for you.
Press `Tab` once to complete; press it twice to list every candidate.

**Commands** complete in the first word position, per transport — offline mode
offers `offer`/`accept`/`finish`/`decrypt`, worker mode offers
`connect`/`listen`/`send`, and aliases (`send`/`encrypt`) both work.

**Peer IDs** complete in any `<peer>` argument slot. A peer becomes completable
the moment it is seen, from either direction:

| You did this | Result |
|--------------|--------|
| `connect <peer_id>` / `offer <peer_id>` | That peer completes for you from then on |
| `listen` received an offer | The sender completes — no need to copy their ID |
| `listen` received a message | The sender completes |
| `load <id>` | Every peer in that identity's saved sessions completes |
| `contacts add <name> <id>` | The alias completes and resolves to the ID |

So the two-party flow needs no ID copying after the first `connect`:

```
# Peer A
╰─❯ connect t1dAbC...            ← the only time you paste a full ID
╰─❯ send t<Tab> hello            ← expands to the full ID

# Peer B
╰─❯ listen                       ← receives A's offer
╰─❯ send <Tab> hi back           ← A's ID is already there
```

**Prefixes work in commands too**, not just in completion: `send t1d hello`
resolves `t1d` to the full ID. If a prefix matches more than one known peer the
command refuses with an "ambiguous peer prefix" error rather than guessing, so a
truncated ID can never send a message to the wrong peer.

**Identities** complete in `load <id>` from the `<id>.json` profiles in the
current directory. Run `peers` to see everything currently completable.

---

## CLI Usage — Direct Transport Entry

```bash
./nextalk worker     # Start directly in Worker transport shell
./nextalk proxy run  # Start directly in Proxy transport shell — note the required `run` subcommand
```

Unlike `worker` (whose root `worker` command runs the shell directly, `cmd/worker/command.go`),
`proxy`'s root command has no `Run`/`RunE` of its own — only its `run`
subcommand does (`cmd/proxy/command.go`). Bare `./nextalk proxy` just prints
usage/help.

---

## Browser / WebAssembly

`cmd/nextalk-wasm` compiles the same `core.Engine` + `crypto.SecurePeer` used by the CLI into a `NexTalk` JavaScript global, including the live worker relay (no reimplementation — `internal/relay/worker.Adapter` runs unmodified under `GOOS=js GOARCH=wasm` since `net/http` transparently uses `fetch()` there as of Go 1.21).

```bash
./cmd/nextalk-wasm/build.sh            # -> web/wasm/{nextalk.wasm,wasm_exec.js}
python3 -m http.server 8000            # must be served over HTTP — file:// will not work
# open http://localhost:8000/web/
```

The JS surface mirrors the CLI one-to-one: `NexTalk.init/id/exportIdentity/importIdentity`, `NexTalk.createOffer/acceptOffer/finishHandshake`, `NexTalk.encrypt/decrypt`, `NexTalk.relay.*` (connectWorker/register/sendOffer/sendAnswer/sendMessage/receive), `NexTalk.contacts.*`, `NexTalk.sessions.*`, and proquint helpers under `NexTalk.encoding.*`. `web/index.html` is a two-tab live-relay demo built on exactly this API. The proxy transport is **not** wired up in wasm (or in the CLI's polymorphic relay path) — `internal/relay/proxy.Adapter.Send` doesn't yet satisfy the `relay.Relay` interface. Full API reference, layout rationale, and worked examples: [`docs/wasm.md`](docs/wasm.md).

---

## Session Persistence

Each peer's state is persisted as a JSON file in the working directory:

```
<peer_id>.json
```

This file contains the long-term identity keys, all active session states (ratchet chains, nonces, skipped keys), and seen Offer IDs for replay detection. **Protect this file** — it contains private key material.

---

## Testing

NexTalk includes a Python integration test harness (`test.py`) that drives the offline CLI as a subprocess:

```bash
python test.py
```

The harness covers:

- **Happy path** — full offer → accept → finish → encrypt → decrypt round-trip
- **Bidirectional messaging** — both Alice→Bob and Bob→Alice
- **Replay attacks** — duplicate Offer IDs rejected at accept
- **Tampered ciphertext** — AEAD authentication failure
- **Cross-peer decryption** — session isolation enforced (Eve cannot read Alice/Bob traffic)
- **Out-of-order messages** — skipped key cache exercised
- **Ratchet advancement** — forward secrecy verified across message sequences

The test runner extracts results from the JSON stdout of each command and asserts on `data.message`, `data.sender`, and error conditions.

---

## Security Properties

| Property               | Mechanism                                        |
|------------------------|--------------------------------------------------|
| Forward secrecy        | Per-message symmetric ratchet (key discarded after use) |
| Break-in recovery      | DH ratchet triggered on new remote key           |
| Post-quantum resistance | Kyber768 KEM + Dilithium3 signatures            |
| Replay protection      | Offer ID deduplication + receive nonce ordering  |
| Identity binding       | Transcript hash ties all pubkeys to handshake context |
| Integrity              | HMAC-SHA3-256 + XChaCha20-Poly1305 AEAD         |
| Peer authentication    | Dual signatures: Ed25519 (classical) + Dilithium3 (PQC) |
| Transport confidentiality | Transport layer only ever handles opaque, already-encrypted bytes |

---

## Configuration

Worker and Proxy transports are configured via a `.env` file in the working directory (`internal/config`):

```env
WORKER_URL=https://your-cloudflare-worker.workers.dev
PROXY_URL=https://your-s3-relay-endpoint
DEBUG=true
```

| Variable | Default if unset |
|----------|-------------------|
| `WORKER_URL` | `""` (empty — worker calls will fail until set) |
| `PROXY_URL` | `http://localhost:8080` |
| `DEBUG` | `false` |

---

## Limitations & Future Work

- **Not production-audited** — research and experimentation only
- `internal/relay/proxy.Adapter.Send` doesn't satisfy the `relay.Relay` interface yet, so the proxy transport can't be used polymorphically the way the worker transport now can (CLI and wasm alike)
- No multi-device identity synchronization
- No persistent mailbox indexing per peer (in-memory only during shell session)
- Transport-layer replay hardening is incomplete
- No formal protocol specification
- Session inspection tooling in shell is minimal

Planned:
- Formal protocol spec (RFC-style)
- Structured event tracing for envelope debugging
- Multi-device key sync design
- Persistent peer mailbox indexing

---

## Design Philosophy

NexTalk cleanly separates four concerns:

1. **Cryptography** (`crypto/`) — primitives only, no protocol decisions
2. **Protocol** (`core/`) — handshake and session logic, no transport assumptions
3. **Transport** (`transport/`) — untrusted relay, no knowledge of payload semantics
4. **Runtime** (`cmd/`) — shell orchestration, no cryptographic decisions

Each layer is independently auditable and testable. The offline CLI exists precisely to make the protocol layer testable without any transport dependency.

---

> ⚠️ NexTalk is a research-grade protocol system. It is not production-audited and is designed for experimentation in secure transport abstraction.
>
> Portions of this codebase were developed with AI assistance. As with any research-grade cryptographic software, independent review of the cryptographic logic (`crypto/`, `core/`) is strongly recommended before any real-world use.