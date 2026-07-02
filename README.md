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
  nextalk/          → Binary entry point (main.go)
  offline/          → Cobra subcommands: init, offer, accept, finish, encrypt, decrypt, run
  worker/           → Worker transport subcommand + registration
  proxy/            → Proxy transport subcommand + registration
  gui/              → TUI shell launcher

core/               → Protocol engine: handshake orchestration, session management
crypto/             → Cryptographic primitives: keys, ratchet, AEAD, HKDF
client/             → Peer identity state + persistent session storage (JSON files)

transport/          → Raw relay adapters: Cloudflare KV (worker.go), S3 (proxy.go)

internal/
  config/           → Environment config loader (.env)
  encoding/         → Base64 utilities
  relay/            → Transport adapter interfaces
    worker/         → Cloudflare Worker adapter
    proxy/          → S3/proxy adapter
  session/          → Session state helpers
```

Each layer has a well-defined trust boundary:

| Layer       | Trust Level                                              |
|-------------|----------------------------------------------------------|
| `crypto`    | Fully trusted — all cryptographic primitives             |
| `core`      | Fully trusted — owns protocol correctness                |
| `client`    | Trusted — manages local identity and session state       |
| `transport` | **Untrusted** — treats all relay infrastructure as hostile |
| `cmd`       | Orchestration only — no cryptographic decisions          |

The transport layer never sees plaintext. It only routes opaque JSON envelopes.

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

## Envelope Format

All transports (offline CLI, worker, proxy) exchange structured JSON envelopes:

```json
{ "type": "offer | answer | message | finish", "data": { ... } }
```

The `data` field always contains the decoded payload as a JSON object — never a string. The transport layer does not interpret payload semantics.

---

## Building

```bash
go build ./cmd/nextalk
# or
go build -o nextalk.exe ./cmd/nextalk
```

Requires Go 1.21+. Dependencies are managed via `go.mod`.

---

## CLI Usage — Offline Mode

Offline mode is a self-contained cryptographic lab with no networking. It is the reference implementation of the protocol and is used for testing, debugging, and manual session bootstrapping.

Each command outputs a JSON envelope to stdout. Envelopes are piped between commands to complete a handshake.

---

### `init` — Create a new peer identity

```bash
./nextalk offline init
```

Generates a fresh Ed25519 + Dilithium3 identity and persists it to `<peer_id>.json` in the working directory.

**Output:**
```json
{ "id": "3tJcNVmRHZ7CFhF1WPUDyECp..." }
```

---

### `offer` — Generate a handshake offer (Initiator, Step 1)

```bash
./nextalk offline offer -i <local_peer_id> -r <remote_peer_id>
```

| Flag | Short | Description              |
|------|-------|--------------------------|
| `--id` | `-i` | Local peer ID (required) |
| `--remotePeer` | `-r` | Recipient peer ID (required) |

Loads `<local_peer_id>.json`, generates ephemeral keys + Kyber768 keypair, signs the bundle with Ed25519 + Dilithium3, and outputs an offer envelope.

**Output:**
```json
{
  "type": "offer",
  "data": {
    "s": "<sender_id>",
    "r": "<recipient_id_bytes>",
    "oid": "<offer_id>",
    "ip": "<ed25519_pub>",
    "p":  "<x25519_pub>",
    "dp": "<dh_pub>",
    "kp": "<kyber768_pub>",
    "lp": "<dilithium_pub>",
    "sg": "<ed25519_sig>",
    "ds": "<dilithium_sig>"
  }
}
```

---

### `accept` — Accept an offer and generate an answer (Responder, Step 2)

```bash
./nextalk offline accept -i <local_peer_id> -o '<offer_envelope_json>'
```

| Flag | Short | Description                          |
|------|-------|--------------------------------------|
| `--id` | `-i` | Local peer ID (required)             |
| `--offerEnvelope` | `-o` | Offer JSON envelope (required) |

Verifies both signatures (Ed25519 + Dilithium3), checks Offer ID for replay, **encapsulates** the initiator's Kyber768 public key to produce `(kyber_ciphertext, shared_secret)`, runs the full handshake, and outputs an answer envelope.

**Output:**
```json
{
  "type": "answer",
  "data": {
    "s":  "<responder_id>",
    "ip": "<ed25519_pub>",
    "p":  "<x25519_pub>",
    "dp": "<dh_pub>",
    "kp": "<kyber768_pub>",
    "kc": "<kyber_ciphertext>",
    "lp": "<dilithium_pub>",
    "sg": "<ed25519_sig>",
    "ds": "<dilithium_sig>",
    "oid": "<offer_id>",
    "r":  "<recipient_id>"
  }
}
```

---

### `finish` — Finalize the session (Initiator, Step 3)

```bash
./nextalk offline finish -i <local_peer_id> -a '<answer_envelope_json>'
```

| Flag | Short | Description                           |
|------|-------|---------------------------------------|
| `--id` | `-i` | Local peer ID (required)              |
| `--answerEnvelope` | `-a` | Answer JSON envelope (required) |

**Decapsulates** the Kyber ciphertext using the initiator's stored private key to recover `shared_secret`, then runs the same handshake derivation. If both peers derived the same shared secret, their session keys will match and the ratchet is active.

**Output:**
```json
{ "type": "finish", "data": { "peer_id": "<remote_peer_id>" } }
```

---

### `encrypt` — Encrypt a message

```bash
./nextalk offline encrypt -i <local_peer_id> -r <remote_peer_id> -m "hello"
```

| Flag | Short | Description                     |
|------|-------|---------------------------------|
| `--id` | `-i` | Local peer ID (required)        |
| `--remotePeer` | `-r` | Target session peer ID (required) |
| `--message` | `-m` | Plaintext message (required)  |

Loads the active session for the remote peer, advances the send ratchet, and outputs the encrypted envelope.

**Output:**
```json
{
  "type": "message",
  "data": {
    "s": "<sender_id>",
    "k": "<dh_ratchet_pub>",
    "n": 0,
    "c": "<ciphertext_bytes>",
    "t": "<hmac_tag>"
  }
}
```

---

### `decrypt` — Decrypt a message

```bash
./nextalk offline decrypt -i <local_peer_id> -c '<message_envelope_json>'
```

| Flag | Short | Description                        |
|------|-------|------------------------------------|
| `--id` | `-i` | Local peer ID (required)           |
| `--cipherText` | `-c` | Message JSON envelope (required) |

Verifies HMAC, resolves the sender session, handles any DH ratchet advancement, and decrypts.

**Output:**
```json
{
  "type": "message",
  "data": {
    "sender":  "<sender_peer_id>",
    "message": "hello"
  }
}
```

---

### `run` — Start the interactive offline REPL

```bash
./nextalk offline run
```

Launches the interactive offline shell with the same commands available as one-liners: `init`, `load`, `offer`, `accept`, `finish`, `encrypt`, `decrypt`, `exit`.

---

## Full Offline Handshake Example

```bash
# Step 0: create identities for Alice and Bob
ALICE=$(./nextalk offline init | jq -r '.id')
BOB=$(./nextalk offline init | jq -r '.id')

# Step 1: Alice creates an offer
OFFER=$(./nextalk offline offer -i "$ALICE" -r "$BOB")

# Step 2: Bob accepts the offer
ANSWER=$(./nextalk offline accept -i "$BOB" -o "$OFFER")

# Step 3: Alice finishes the handshake
./nextalk offline finish -i "$ALICE" -a "$ANSWER"

# Step 4: Alice sends an encrypted message to Bob
MSG=$(./nextalk offline encrypt -i "$ALICE" -r "$BOB" -m "hello world")

# Step 5: Bob decrypts it
./nextalk offline decrypt -i "$BOB" -c "$MSG"
# → {"type":"message","data":{"sender":"<alice_id>","message":"hello world"}}
```

---

## CLI Usage — TUI / GUI Mode

```bash
./nextalk gui
```

Launches the full TUI transport selector:

```
╔════════════════════════════════════════╗
║               NexTalk CLI              ║
╚════════════════════════════════════════╝

  1. Offline Mode  (Manual Cryptography Lab)
  2. Worker Mode   (Cloud Relay)
  3. Proxy Mode    (Anonymized Routing)
  4. Exit
```

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
| `switch` / `exit` | Return to the main transport selector |

The `listen` command handles the full handshake automatically:
- Incoming **offer** → auto-accept and send answer
- Incoming **answer** → auto-finish and activate session
- Incoming **message** → decrypt and store in mailbox

---

## CLI Usage — Direct Transport Entry

```bash
./nextalk worker   # Start directly in Worker transport shell
./nextalk proxy    # Start directly in Proxy transport shell
```

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
| Transport confidentiality | Transport layer sees only opaque JSON envelopes |

---

## Configuration

Worker and Proxy transports are configured via a `.env` file in the working directory:

```env
WORKER_URL=https://your-cloudflare-worker.workers.dev
PROXY_URL=https://your-s3-relay-endpoint
```

---

## Limitations & Future Work

- **Not production-audited** — research and experimentation only
- No multi-device identity synchronization
- No persistent mailbox indexing per peer (in-memory only during TUI session)
- Transport-layer replay hardening is incomplete
- No formal protocol specification
- Session inspection tooling in TUI is minimal

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
4. **Runtime** (`cmd/`) — CLI/TUI orchestration, no cryptographic decisions

Each layer is independently auditable and testable. The offline CLI exists precisely to make the protocol layer testable without any transport dependency.

---

> ⚠️ NexTalk is a research-grade protocol system. It is not production-audited and is designed for experimentation in secure transport abstraction.
>
> Portions of this codebase were developed with AI assistance. As with any research-grade cryptographic software, independent review of the cryptographic logic (`crypto/`, `core/`) is strongly recommended before any real-world use.