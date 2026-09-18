# Real scenarios — transports in production use

All scenarios below run with built release binaries. No `go run`,
no rebuilds, no test harnesses. Each was executed end-to-end during
development (see commit history); reproduce them verbatim. Scenario E runs
entirely inside the interactive shell (`docs/shell.md`); A–D use one-shot
commands — same handlers, same behavior.

Conventions: Alice and Bob work in separate directories (identity files
`<id>.json` live per directory). `$T` is a scratch transports dir:

```bash
export NEXTALK_TRANSPORTS_DIR=$PWD/transports   # bash
$env:NEXTALK_TRANSPORTS_DIR = "$PWD/transports" # PowerShell
```

---

## Scenario A — local chat via relay-example (third-party transport)

Proves: third-party install with no rebuild, shared dispatch, E2E crypto.

```bash
# Build + package the example (once, by its own author)
cd example-transports/relay-example
go build -o relay-example . && zip relay-example.ntx manifest.json relay-example

# Install (NexTalk binary untouched)
nextalk transport install relay-example.ntx --enable
nextalk transport list
# relay-example  enabled   v1.0.0      caps=[message]

# Identities + file handshake
mkdir -p alice bob
(cd alice && nextalk offline init --format json)  # -> ALICE
(cd bob   && nextalk offline init --format json)  # -> BOB
(cd alice && nextalk offline offer -i ALICE -r BOB -o offer.bin)
cp alice/offer.bin bob/
(cd bob && nextalk offline accept -i BOB -f offer.bin -o answer.bin)
cp bob/answer.bin alice/
(cd alice && nextalk offline finish -i ALICE -f answer.bin)

# Mailbox ids (this transport: hex(sha256(ed_pub)[:16]); ed pub = peer-ID prefix)
relay-example mailbox --pub <ALICE_ED_HEX>   # -> AMBOX
relay-example mailbox --pub <BOB_ED_HEX>     # -> BMBOX
(cd alice && nextalk transport attach relay-example --mailbox AMBOX --secret $(rand64) --shard local)
(cd bob   && nextalk transport attach relay-example --mailbox BMBOX --secret $(rand64) --shard local)

# Chat (core encrypts; transport couriers opaque frames)
(cd alice && nextalk offline encrypt -i ALICE -r BOB -m "hello bob" -o msg.bin)
(cd alice && relay-example wrap --type 3 -f msg.bin > frame.bin)
(cd alice && nextalk transport send-frame relay-example --to BOB -f frame.bin)
(cd bob && nextalk transport poll relay-example -i BOB)
# [+] Message from <ALICE> (utf-8) — stored in mailbox:
# hello bob
```

## Scenario B — messages over FileRelay (courier bridge + filerelayd)

Proves: scoped-credential model, router/shard/bridge interop, shared dispatch.

```bash
# Server (single-binary demo; production splits router/shard + KV)
filerelayd --addr 127.0.0.1:8080 --server-secret <64hex>  # keep running
R=http://127.0.0.1:8080

# Bridge package/install (entry carries .exe on Windows)
go build -o filerelay-bridge ./transports/filerelay/bridge
zip filerelay.ntx manifest.json filerelay-bridge
nextalk transport install filerelay.ntx --enable
nextalk transport config filerelay "{\"router_url\":\"$R\"}"

# Identities + handshake (same as scenario A)

# Mailboxes: the bridge mints scoped-credential mailboxes (tag derived from peer
# ID internally); core keeps bearers. -i is required (no --user flag).
(cd alice && nextalk transport register filerelay -i ALICE --router $R)
# {"mailbox_id":"...","read_secret":"...","shard_url":"...","router_url":"...","attached":true}
(cd bob   && nextalk transport register filerelay -i BOB   --router $R)
# Recipient shares mailbox_id + shard_url with the sender out-of-band.
# (register auto-attaches; explicit attach below is optional / shows the manual form)
(cd alice && nextalk transport attach filerelay --mailbox <A> --secret <S> --shard $R --router $R)
(cd bob   && nextalk transport attach filerelay --mailbox <B> --secret <S> --shard $R --router $R)

# Chat (explicit recipient address; scoped mailboxes are unguessable by design)
(cd alice && nextalk offline encrypt -i ALICE -r BOB -m "hello via filerelay" -o msg.bin)
(cd alice && filerelay-bridge wrap --type 3 -f msg.bin > frame.bin)
(cd alice && nextalk transport send-frame filerelay --mailbox <B> --shard $R -f frame.bin)
(cd bob && nextalk transport poll filerelay -i BOB)
# [+] Message from <ALICE> (utf-8) — stored in mailbox:
# hello via filerelay
```

## Scenario C — files over FileRelay (binary-transfer)

Proves: whole-file E2E encryption, chunked resumable upload, hash-verified
download, byte-identical delivery. Continues scenario B's setup.

```bash
# Alice encrypts + uploads (transfer_id + manifest are the handoff)
(cd alice && nextalk transport xfer-send filerelay -i ALICE --to BOB \
  --mailbox <B> --shard $R -f photo.bin)
# {"transfer_id":"...","manifest":"...","chunks":"3"}
# Relay transfer_id + manifest to Bob (message, QR, anything).

# Bob downloads + verifies + decrypts
(cd bob && nextalk transport xfer-recv filerelay -i BOB --from ALICE \
  --transfer <id> --mailbox <B> --secret <S> --manifest <b64> -o photo.out.bin)
# Received 88000 bytes -> photo.out.bin
cmp photo.bin photo.out.bin   # identical
```

Interrupted uploads resume: re-run `xfer-send` steps manually is unnecessary —
`xfer-recv` reports `transfer incomplete (highest=N, ...)` and `xfer-send`
re-put is idempotent per chunk, so re-running the send side fills only gaps.

## Scenario D — ticket share: upload to your relay, send the secret in a message

Proves the unified model: one relay for messages, another for files
(or the same one twice). Alice uploads to **her own** mailbox space, then
sends the download ticket inside an ordinary E2E message; Bob fetches with
the ticket alone — no mailbox, no relay session, no read_secret. Continues
scenario B's setup (both registered).

```bash
# Alice uploads to HER mailbox (sender-owned; quota counts against her)
(cd alice && nextalk transport xfer-send filerelay -i ALICE --to BOB \
  --mailbox <A> --shard $R -f photo.bin)
# {"transfer_id":"...","manifest":"...","chunks":"3",
#  "ticket":"<base64 of the NanoPack ticket>"}
# (stderr also shows a human summary like: file "photo.bin" (88000 bytes, ...))

# Alice sends the ticket string as a message over ANY message relay
# (here: relay-example; a dedicated ticket-only message works the same).
# The ticket is binary (NanoPack schema 13) carried as one base64 string —
# JSON appears nowhere on the wire; it is only ever display text.
(cd alice && nextalk offline encrypt -i ALICE -r BOB -m '<ticket-base64>' -o ticketmsg.bin)
(cd alice && relay-example wrap --type 3 -f ticketmsg.bin > ticketframe.bin)
(cd alice && nextalk transport send-frame relay-example --to BOB -f ticketframe.bin)

# Bob polls, reads the ticket message, fetches with the ticket alone
(cd bob && nextalk transport poll relay-example -i BOB)
(cd bob && nextalk transport xfer-recv filerelay -i BOB --from ALICE \
  --ticket '<ticket-base64>' -o photo.out.bin)
# Received 88000 bytes -> photo.out.bin
cmp photo.bin photo.out.bin   # identical
```

Why this is safe: the ticket is a download-only bearer (resume/get, never
mailbox reads, uploads, complete, or cancel), it dies with the transfer
(expiry/cancel), and it travels inside E2E-encrypted message content — the
relay sees only opaque chunks, the message relay only an opaque envelope.

## Scenario E — the whole file workflow without leaving the shell

Same moving parts as B + D, but entirely interactive. Assumes scenario B's
server and installs; start from identities created in scenario A.

```text
╭─[nextalk:-@-]
╰─❯ use identity alice
╭─[nextalk:alice@-]
╰─❯ use relay filerelay
╭─[nextalk:alice@filerelay]
╰─❯ transport register --router $R
Mailbox a1b2c3...d4e5 minted and attached.
read_secret: ********
╰─❯ transport attach --mailbox <A> --shard $R --router $R
# (already auto-attached by register; shown for the manual / re-attach form)
read secret (hidden):
╰─❯ peer address bob --mailbox <B> --shard $R
Address recorded for bob....
╰─❯ peer connect bob
Offer sent to bob.... — bob answers on poll; then poll to finish.
╰─❯ transport poll
[+] Session established with bob....
╰─❯ xfer send --to bob -f ./movie.mp4 --mailbox <A> --shard $R
✓ Transfer created

ID:
abc123...

Ticket:
BgEB...

╰─❯ message send bob "Here is the file" --ticket BgEB...
Message sent to bob....
╰─❯ context
Identity:
  alice...
Relay:
  filerelay
Active transfers:
  abc123...  movie.mp4 (88000 bytes)
```

Recipient, in any shell (Bob recorded Alice's address once, so her offer
and the auto-answer route without flags):

```text
╰─❯ use identity bob
╰─❯ use relay filerelay
╰─❯ peer address alice --mailbox <A> --shard $R
Address recorded for alice....
╰─❯ transport poll
[+] Message from alice... (utf-8) — stored in mailbox:
Here is the file
BgEB...
╰─❯ xfer inspect BgEB...
Transfer abc123...
  file:     movie.mp4 (88000 bytes, 3 chunks)
  shard:    http://127.0.0.1:8080
  secret:   ********
╰─❯ xfer recv BgEB... -o movie.out.mp4
Received 88000 bytes -> movie.out.mp4
╰─❯ xfer resume --transfer abc123... --ticket BgEB... --shard $R
Transfer abc123... complete: 3/3 chunks.
```

Scripting the same flow non-interactively — pipe it, or use the one-shot
twins (`nextalk transport xfer-send ... --json | process-ticket`); `--json`
emits exactly one document per command on stdout with exit codes.

## WASM transports

```bash
# .ntx packages whose manifest entry ends .wasm run sandboxed (wazero):
nextalk transport install queue.ntx --enable   # entry: queue.wasm
nextalk transport list                          # runs in-process, no syscalls
```

The hand-assembled queue module in `internal/transport/wasm_*_test.go` is the
ABI reference; `TestWASMInstallToRun` proves package → install → run.
