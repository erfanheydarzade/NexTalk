# Security Policy

> **Note:** NexTalk is research-grade cryptographic software and has **not**
> been independently audited. Do not use it to protect real-world sensitive
> data. See [Limitations](#scope-and-limitations).

## Supported Versions

Security fixes are provided on the latest tagged release on the
[Releases page](https://github.com/erfanheydarzade/NexTalk/releases)
and on `main`.

| Version | Supported |
|---------|-----------|
| Latest release (`main` tip) | ✅ |
| Older tagged releases | ❌ — please upgrade and re-test before reporting |

Prebuilt binaries and the WebAssembly bundle are published per release;
a local `go build` reports version `dev` (see `docs/RELEASING.md`).

## Reporting a Vulnerability

**Please do not open a public GitHub issue for a suspected vulnerability.**

Use one of these private channels:

1. **Preferred:** [GitHub private vulnerability reporting](../../security/advisories/new)
   (Security tab → Advisories → New draft advisory), or
2. Open a minimal public issue that says only "possible security issue —
   please contact me" with no technical details, and the maintainer will
   follow up privately.

### What to include

- Affected version/commit and platform (`nextalk version`, OS/arch, or
  `GOOS`/`GOARCH` for wasm builds).
- Transport and mode: `offline`, `worker`, `proxy`, `shell`, or browser/wasm
  (`web/`, `cmd/nextalk-wasm`).
- Step-by-step reproduction (commands, flags, minimal inputs). Prefer
  offline-mode repros (`cmd/offline`) since they need no relay server.
- Impact assessment: what an attacker gains (decryption, forgery, identity
  spoofing, replay, DoS, secret leak) and what prerequisites apply
  (network position, relay control, local file access, etc.).
- Logs, transcripts, or PoC output. **Redact all key material** (see below).

### Handling sensitive files

Never attach unredacted secrets to any report, public or private:

- `<peer_id>.json` identity files contain long-term private keys
  (Ed25519, Dilithium3) and session state.
- `<id>.mailbox.json`, `<id>.contexts.json`, `<id>.policies.json`,
  `<id>.deliveries.json` (and their `.np` counterparts) may contain
  plaintext history.
- `.env` may contain relay URLs and bearer secrets (`WORKER_URL`,
  `PROXY_URL`, mailbox secrets).
- `offer.bin` / `answer.bin` / pasted envelopes are safe to share only if
  they contain no private keys — when in doubt, generate fresh throwaway
  identities for the repro.

### What happens next

- Acknowledgement within **7 days**.
- Triage and severity assessment (cryptographic break vs. hardening vs.
  out of scope).
- Fix on `main`, plus a new release if the issue affects the latest tag.
- Public disclosure via a GitHub Security Advisory and release notes once a
  fix is available. Reporter credit on request.
- There is **no bug-bounty program**; this is an unfunded research project.

### Safe harbor

Good-faith security research against your own local builds and throwaway
identities is welcome. Please do not:

- Attack other users' mailboxes, relay accounts, or Cloudflare/S3 backends
  you do not own.
- Exfiltrate, retain, or disclose other users' plaintext or private keys.
- Perform DoS against shared relay infrastructure.
- Spam `listen`/`poll` loops or credential-guessing against public relays.

Research that stays within these bounds will be treated as good-faith even
if your tooling trips automated abuse detection.

## Scope and Limitations

### In scope (highest priority)

- `crypto/` — primitives, ratchet, AEAD, HKDF, key handling.
- `core/` — handshake orchestration, session management, transcript binding,
  signature verification, replay/nonce enforcement.
- `client/` + `internal/session`, `internal/multimsg`, `internal/mailbox` —
  session persistence, skipped-key cache, context/policy enforcement where
  it has cryptographic consequences.
- `cmd/offline` — the reference protocol implementation (preferred repro
  surface).
- `internal/wasmbridge`, `cmd/nextalk-wasm`, `web/` — only for bugs that
  weaken the same protocol guarantees in the browser build.

### Lower priority / defense-in-depth

- `transport/`, `internal/relay/*` — treated as **untrusted by design**; the
  relay only ever sees opaque, already-encrypted bytes. Relay compromise
  alone (observation, reordering, dropping) is the assumed threat model, not
  a vulnerability. Relay bugs count as security issues when they enable
  forgery acceptance, identity confusion, plaintext leak, or key exfiltration
  to the transport.
- `cmd/`, shell completion/prompt handling — command injection, path
  traversal (`-f`/`-o`), TTY binary-output guards, ambiguous peer-prefix
  resolution.

### Out of scope

- Findings that require the attacker to already hold the victim's
  `<peer_id>.json` or other local secret files — local key compromise is
  total compromise by design ("Protect this file" in the README).
- `*.log` verbosity, version-string disclosure (`dev` vs. tag).
- Missing server-side ACKs/delivery receipts, multi-device sync, or other
  items already listed under README "Limitations & Future Work", unless you
  show a concrete cryptographic break.
- Third-party dependencies (CIRCL, nanopack, cobra, wazero, x/crypto) —
  report those upstream, unless NexTalk uses them unsafely.
- Social engineering, physical access, or compromised build machines.

### Known limitations (not vulnerabilities)

These are documented trade-offs; reports restating them without a new
exploit will be closed as known issues:

- Not production-audited; no formal protocol specification yet.
- Removing a group recipient does not revoke messages already delivered
  (fan-out uses independent 1:1 ciphertexts — see `docs/groups.md`).
- Mailbox/context/session files are last-writer-wins per process; concurrent
  writers can drop writes.
- Transport-layer replay hardening is incomplete beyond offer-ID dedup and
  receive-nonce ordering.
- AI assistance was used in development; independent review of `crypto/`
  and `core/` is explicitly recommended (see README footer).

## If You Think You Are Affected

1. Stop using the affected version; upgrade to the latest release.
2. Treat any exposed `<peer_id>.json` as compromised: generate a fresh
   identity (`offline init` / `worker init`) and re-establish sessions
   (offer → accept → finish) rather than copying old state forward.
3. Rotate relay mailbox credentials (`transport register`/`attach`) and any
   leaked `.env` secrets.
4. Past ciphertext remains decryptable by anyone who held the session keys
   at the time — rotation provides forward secrecy only for future messages.
