# Contributing to NexTalk

Thanks for stopping by. NexTalk is a research-grade hybrid post-quantum
messaging protocol runtime in Go — not a chat app. The most valuable
contributions are careful, well-tested changes to the protocol core,
plus the docs and tooling that keep it auditable.

> **Research software:** NexTalk is not production-audited. Cryptographic
> changes need extra scrutiny — see [Working on crypto](#working-on-crypto).

## Ground Rules

- **License:** By contributing you agree your work is licensed under the
  [Apache License 2.0](LICENSE) (see `LICENSE` §5, Submission of
  Contributions).
- **Be kind and precise.** Review focuses on correctness, threat model, and
  testability. Disagree on technical grounds, with evidence.
- **Security first:** suspected vulnerabilities follow
  [SECURITY.md](SECURITY.md) — do not open public issues for them.
- **No surprising scopes:** bug fixes and docs are always welcome; new
  transports, wire-format changes, or crypto swaps deserve an issue first
  so wire compatibility and the threat model can be discussed.

## Repository Tour

```
cmd/nextalk          → binary entry point (main.go)
cmd/offline          → offline lab: init, offer, accept, finish, encrypt, decrypt, run
cmd/worker, cmd/proxy, cmd/shell, cmd/contacts, cmd/transports
core/                → protocol engine: handshake, session management
crypto/              → primitives: keys, ratchet, AEAD, HKDF
client/              → peer identity + persistent session storage (<id>.json)
transport/           → raw relay adapters (Cloudflare KV, S3)
internal/            → codec, config (.env), contacts, registry, relay,
                       session, wasmbridge (one file per concern)
web/                 → browser demo loading the wasm bundle
docs/                → framing, groups, serialization, shell, transports, wasm, releasing
test.py              → Python black-box protocol suite (offline CLI)
```

Trust boundaries: `crypto` and `core` are fully trusted; `client` manages
local secrets; `transport` is **untrusted** (opaque bytes only); `cmd` is
orchestration with no crypto decisions. Full map: `README.md`.

## Prerequisites

- **Go 1.25+** (see `go.mod`).
- **Python 3** (stdlib only) for `test.py`.
- Optional: `python3 -m http.server` for serving the wasm demo; a Cloudflare
  Worker / S3 relay URL only if you touch `worker`/`proxy` paths
  (`.env.example` → `.env`).

## Quick Start

```bash
git clone https://github.com/erfanheydarzade/NexTalk.git
cd NexTalk

go build ./cmd/nextalk        # or: go build -o nextalk.exe ./cmd/nextalk
go vet ./...
go test ./... -v
python test.py                # offline offer→accept→finish→encrypt→decrypt suite
```

Copy `.env.example` to `.env` only if you need relay-backed commands:

```env
WORKER_URL=https://your-cloudflare-worker.workers.dev
PROXY_URL=https://your-s3-relay-endpoint
DEBUG=false
```

Never commit `.env`, `<peer_id>.json`, `*.mailbox.json`, `*.np`, `*.ntx`,
or build output — all are gitignored for a reason (they hold keys).

## Workflow

1. **Discuss first for risky changes:** crypto primitives, handshake/KDF
   transcript, `SecureMessage` wire fields, nanopack schema IDs, session-file
   formats, transport envelopes. Open an issue describing the threat model
   and compatibility impact.
2. **Branch from `main`:** `feat/<x>`, `fix/<x>`, `docs/<x>`.
3. **Keep layers clean:** crypto decisions stay in `crypto`/`core`; transports
   stay payload-opaque; CLI/shell code stays orchestration-only.
4. **Test like CI does** (see `.github/workflows/ci.yml`):
   ```bash
   go mod tidy && git diff --exit-code go.mod go.sum
   gofmt -l .
   go vet ./...
   go build ./...
   go test ./... -v
   python test.py
   ```
   All five must pass. `gofmt` failures and untidy `go.mod`/`go.sum` fail CI.
5. **Document behavior:** update `README.md` CLI sections and the relevant
   `docs/*.md` (framing, groups, serialization, shell, transports, wasm)
   when flags, envelopes, stores, or flows change.
6. **Open a PR against `main`** with: what/why, threat-model notes for
   security-relevant changes, repro/verification steps, and docs updated.
   Conventional prefixes (`feat:`, `fix:`, `docs:`) feed the release
   changelog (`docs/RELEASING.md`). One logical change per PR.

## Coding Guidelines

- **Go style:** `gofmt`-clean, `go vet`-clean. Follow surrounding code;
  keep exported APIs small and commented.
- **No crypto in `cmd/`:** wire CLI/shell through `core`/`crypto` instead of
  reimplementing checks. New subcommands share handlers with their shell
  twins where applicable.
- **Encoding flags:** `--in`/`--out` accept `raw`/`b64`/`hex` (`decrypt --in`
  defaults to `b64`); `--format` accepts `human`/`json`. Reject anything
  else with a clean error — no cobra usage dumps on protocol failures
  (`SilenceErrors`/`SilenceUsage`).
- **Peer prefixes:** truncated IDs must resolve unambiguously or refuse —
  never guess between matches.
- **Errors:** human mode goes to stderr, machine-readable `--format json`
  carries `error` keys; `worker --help` must keep listing real subcommands.
- **Dependencies:** prefer stdlib; justify new `go.mod` entries and keep
  `go mod tidy` clean.

## Working on Crypto

- Touch `crypto/` and `core/` only with a clear rationale and tests proving
  the security property (happy path + forgery/tamper/replay/ordering cases
  in `test.py` style).
- **Do not renumber nanopack field IDs** on `crypto.SecureMessage` (or any
  shipped schema) — IDs are the wire contract. After legitimate tag changes,
  regenerate with:
  ```bash
  go run github.com/erfanheydarzade/nanopack/cmd/bingen
  ```
  and note the compat impact in the PR and `docs/serialization.md`.
- Handshake/transcript strings (e.g. `ML-KEM-ECC-Hybrid-Transcript-v1`),
  HKDF info labels, and AAD construction are consensus-critical — changing
  them forks the protocol. Flag prominently.
- Keep tests asserting: chain-key evolution, HMAC-then-AEAD rejection,
  nonce ordering, skipped-key cache bounds (`maxSkip = 1000`), session
  isolation across peers, and that failed decrypts persist no state.

## Working on Transports

- Transports carry opaque frames only — no plaintext inspection, no private
  keys on the RPC path. See `docs/transport-runtime.md`,
  `docs/transport-cli.md`, `docs/adding-a-transport.md`.
- Envelope changes need cross-references: offline JSON paste envelope vs.
  worker `0x01`–`0x04` raw prefix vs. proxy `{type, data}` JSON
  (`README.md` → Wire Formats, `docs/framing.md`).
- End-to-end runs to follow: `docs/real-scenario.md`.

## Working on Wasm / Web

- `cmd/nextalk-wasm` reuses the same `core.Engine` + `crypto.SecurePeer` —
  do not reimplement protocol logic in JS.
- Build with `./cmd/nextalk-wasm/build.sh`, serve over HTTP
  (`python3 -m http.server`), never `file://`. Details: `docs/wasm.md`.

## Tests

| Suite | Command | Covers |
|-------|---------|--------|
| Go unit tests | `go test ./... -v` | packages incl. ratchet, session, relay, shell |
| Protocol suite | `python test.py` / `python test.py -v` / `python test.py NexTalkHappyPath` | offer→finish round-trip, bidirectional, replay, tamper, isolation, out-of-order, ratchet |
| Single binary | `NEXTALK_BIN=path/to/nextalk python test.py` | skip rebuild, test existing binary |

Isolate identity state per test (temp dirs — `<peer_id>.json` lives in CWD),
and never commit test artifacts (`.testbuild/`, `*.bin`, `*.json`).

## Releases

Maintainers cut releases via `.github/workflows/release.yml`
(`docs/RELEASING.md`): semver tag → `go vet` + `go test` → GoReleaser
archives + wasm bundle → GitHub Release with generated changelog.
Contributors just need the conventional commit prefixes; no manual
changelog edits.

## Getting Help

- Questions and ideas: open a GitHub issue (docs, behavior, proposal).
- Security-sensitive matters: follow [SECURITY.md](SECURITY.md).
- Release process: [`docs/RELEASING.md`](docs/RELEASING.md).
