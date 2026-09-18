# `nextalk transport` — command reference

Runtime management for external transport modules. Transports live outside
the binary (`.ntx` packages); these commands install, start, and drive them.
Design: [`transport-runtime.md`](transport-runtime.md). Worked runs:
[`real-scenario.md`](real-scenario.md). Third-party guide:
[`adding-a-transport.md`](adding-a-transport.md). Interactive twin:
[`shell.md`](shell.md) — every command below also runs in the shell
(`transport poll` → `transport poll`, `transport xfer-send` → `xfer send`),
sharing handlers verbatim, so behavior is identical in both frontends.

Global flag on every command: `--transports-dir <dir>` (default
`$NEXTALK_TRANSPORTS_DIR`, else the user config dir). Transports are
**disabled by default**; installs are hash-pinned and re-verified on start.

## Output modes and secrets

Repo-wide rule, enforced by the shared handlers:

- **stdout** — machine-readable output (`--json`: exactly one document).
- **stderr** — logs and human UI.

Secret values (mailbox `read_secret`, bearer flags) print as `********`
unless `--show-secrets` is passed; `--json` machine output always carries
real values. The shareable transfer *ticket* (base64 NanoPack) prints in
full — it is the designed handoff artifact. Shell equivalents: commands
take the same `--json`/`--show-secrets` flags, and `--secret`-style flags
prompt with hidden input when omitted instead of failing.

## `transport list`

```bash
nextalk transport list
# Installed transports:
#
#   filerelay      enabled   v1.0.0      caps=[message,binary-transfer]
#   relay-example  disabled  v1.0.0      caps=[message]
```

## `transport install <package.ntx> [--enable]`

Validates the manifest (fail closed on unknown capabilities/permissions),
extracts `manifest.json` + entry binary, pins the package hash. New installs
default to disabled unless `--enable` is passed.

## `transport remove <id>`

Stops a running transport, deletes its directory and all state (enabled
flag, hash pin, attachments, config).

## `transport enable <id>` / `transport disable <id>`

`disable` stops a running transport first, then marks it disabled. A
crashing transport is auto-disabled (quarantined) by `StartEnabled`.

## `transport status [<id>]`

With an id: `filerelay v1.0.0 api=1 enabled=true running=false
caps=[message binary-transfer] perms=[network storage]`. Without: lists
running transports.

## `transport config <id> <json>`

Stores an opaque config blob passed to the transport at the next start.
Example (FileRelay bridge needs its router):

```bash
nextalk transport config filerelay '{"router_url":"http://127.0.0.1:8080"}'
```

## `transport attach <id> --mailbox <hex> --secret <hex> --shard <url> [--router <url>]`

Subscribes a mailbox for polling. `--mailbox`: 32 lowercase hex (16B);
`--secret`: 64 hex (32B bearer — never an identity key); `--shard` required.

## `transport detach <id> --mailbox <hex>`

Unsubscribes a mailbox.

## `transport poll <id> -i <peer> [--mailbox <hex>] [--limit N] [--format human|json]`

Starts the transport if enabled-but-stopped, pushes stored attachments over
RPC, polls up to `--limit` (default 32, max 32) frames per mailbox, and runs
every frame through shared dispatch — decrypting with `-i`'s sessions and
persisting to its mailbox, exactly like `worker listen`. Session progress is
saved afterwards. Replies (handshake answers) go back out over the same
transport. `--mailbox` restricts the poll to one attachment.

## `transport send-frame <id> [--to <peer|pub> | --mailbox <hex> --shard <url>] -f frame.bin`

Delivers one already-encrypted layer-1 frame file (`[type][payload]`,
≤40 KiB). `--to` takes a peer ID or 64-hex Ed25519 pubkey (deterministic
transports like relay-example derive the mailbox from it); `--mailbox` +
`--shard` address an explicit recipient mailbox (required for
address-shared transports like filerelay, whose scoped mailboxes are
unguessable from the peer key).

## `transport register <id> -i <peer> [--router <url>]`

Mints a mailbox via the transport's scoped credential (FileRelay bridge:
per-identity keypair — tag derived internally as `hex(sha256(peerID)[:8])`,
so two peers never collide on the same mailbox). `-i/--id` is required in
one-shot CLI (no session fallback). `--router` is optional when stored via
`transport config <id> '{"router_url":"..."}'` or a prior attach. Prints
JSON with `mailbox_id`, `read_secret`, `shard_url`, `router_url` (`user_tag`
is internal and no longer exposed) and auto-attaches the mailbox — no manual
`attach` needed; re-register upserts and refreshes `read_secret` on rotation.
Keep `read_secret` private.

## `transport resolve <id> --to <peer|pub> --router <url>`

Maps a recipient to `{"mailbox_id","shard_url"}`. For scoped-credential
transports this only hits mailboxes registered under the matching key.

## `transport xfer-send <id> -i <peer> --to <peer> [--mailbox <hex> --shard <url>] -f <file> [--chunk-size N]`

Encrypts the whole file with the 1:1 session (cap 8 MiB, default 32 KiB
chunks), uploads chunk-by-chunk (idempotent re-put fills gaps), seals the
transfer, and prints `{"transfer_id","manifest","chunks","ticket"}`. `--to`
selects the encryption session (required); `--mailbox`/`--shard` select the
upload address: the **recipient's** mailbox for direct delivery, or your
**own** mailbox for a ticket share (upload to your relay, send the ticket
in a message). The `ticket` is base64 NanoPack (schema 13: version,
transfer_id, download secret, shard, embedded manifest, sender — all raw
bytes, no hex): paste that one string into any E2E message. It is the
"transfer negotiation message": file metadata + download bearer, nothing
else. A human-readable summary is also printed to stderr
(`filetransfer.Ticket.Describe` — display only, never parsed).

## `transport xfer-recv <id> -i <peer> --from <peer> (--ticket <base64> | --transfer <hex> --mailbox <hex> --secret <hex> --manifest <b64>) -o <out>`

Two modes. **Ticket mode** (`--ticket`): everything arrives in one E2E
message — transfer, download secret, shard, manifest. No mailbox, no
session on the relay, no read_secret. **Mailbox mode** (explicit flags):
resume/get with the recipient mailbox bearer.

Both modes resume (refuse cleanly when chunks are still missing), download
each chunk with per-chunk hash verification, reassemble, decrypt, and write
the file (0600). `--from` must match the actual sender or decryption is
rejected. Tickets are download-only and die with the transfer; share them
only inside encrypted messages.

## `transport xfer-resume <id> --transfer <hex> [--mailbox <hex> --secret <hex> | --ticket <base64> --shard <url>]`

Progress without downloading: highest-contiguous chunk, chunk count, and
missing ranges. Ticket mode needs no mailbox credentials.

## `transport xfer-cancel <id> --transfer <hex> --mailbox <hex> --secret <hex>`

Abort a transfer after confirmation. Mailbox-owner auth only — download
tickets never cancel, so a recipient cannot destroy the sender's upload.

## `transport xfer-inspect <id> --ticket <base64>`

Decode a ticket with zero network I/O: transfer id, file, sizes, shard,
sender. The download secret prints redacted unless `--show-secrets`.
