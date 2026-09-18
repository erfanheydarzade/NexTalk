# NexTalk shell — the primary interface

`nextalk shell` is a complete operational interface over the whole
transport ecosystem: identities, contacts, mailboxes, runtime transports,
messages, handshakes, and end-to-end file transfers — without leaving the
prompt. Every shell command runs the same shared handler as its one-shot
CLI twin (`internal/transportops`), so behavior can never drift between
the two frontends.

```text
╭─[nextalk:alice@filerelay]
╰─❯ help
```

## Concepts

- **Session.** The shell remembers who you are (`use identity alice`) and
  which relay you use (`use relay filerelay`). Commands fall back to the
  session instead of demanding `-i`/`--via` every time. `context` shows the
  session; nothing secret is ever written to disk for it.
- **Commands are modular.** Each command self-registers with a name,
  aliases, description, arguments, flags, and handler
  (`internal/shellcmd`, `cmd/shell/commands.go`) — there is no giant
  switch/case, and `help`, Tab completion, and suggestions all read the
  same registry, so they can never disagree.
- **Legacy shells still exist.** `switch <name>` enters the old
  per-transport sub-shells (offline, worker, proxy). They keep working
  unchanged; new work belongs in the unified tree.

## Output modes

Repo-wide rule, enforced by the shared handlers:

- **stdout** — machine-readable output only.
- **stderr** — logs and human UI only.

In the interactive shell both streams reach your terminal, so `xfer send`
prints a friendly `✓ Transfer created` card. With `--json` (per command)
or `set json on`, stdout carries exactly one JSON document per command —
pipe-safe for scripts. Exit codes follow: `0` clean, nonzero on error.

## Secrets

Secret values (read_secret bearers, download tickets' raw secret is part of
the shareable ticket artifact and prints in full, but mailbox `read_secret`
and private keys) print as `********` in human output unless you explicitly
opt in:

```text
nextalk> transport register --router $R
Mailbox a1b2c3...d4e5 minted and attached.
read_secret: ********
```

- `--show-secrets` reveals values for one command; `set show-secrets on`
  reveals them session-wide.
- `--json` machine output always carries real values (explicit request).
- The shell never writes history to disk: history lines can contain pasted
  blobs and bearers, so history is in-memory only (`history` lists it).
- `transport attach --secret` (and `xfer` secret flags) prompt with hidden
  input when the flag is omitted — no shoulder-surfing, no shell history
  entry containing the value... (the command line itself is still recorded;
  pass secrets via prompt, not flags, when that matters).

## Command reference

Flags use `--name value`, `--name=value`, or `-n value`; booleans are bare
(`--json`). `--help` after any command shows its full usage. `[transport]`
positionals fall back to the session relay; `-i/--id` falls back to the
session identity.

### Transport management (`transport ...`)

Same operations as `nextalk transport ...`:

| Command | Does |
|---|---|
| `transport list [--json]` | installed transports, enabled/running/caps |
| `transport install <package.ntx> [--enable]` | validate, extract, hash-pin |
| `transport remove <id>` | confirm, then stop/delete/forget |
| `transport enable\|disable <id>` | flip the enabled flag (disable stops) |
| `transport status [id]` | one transport, or every running one |
| `transport config <id> <json>` | opaque config blob for next start |
| `transport attach --mailbox M --secret S --shard U [--router R]` | subscribe a mailbox (secret prompts hidden) |
| `transport detach --mailbox M` | unsubscribe (confirms) |
| `transport poll [--mailbox M] [--limit N] [--format human\|json]` | fetch + dispatch (decrypt + store, like worker listen) |
| `transport send-frame [--to P \| --mailbox M --shard U] -f frame.bin` | deliver a pre-encrypted frame |
| `transport register [--router U]` | mint a mailbox for the active identity (tag derived internally; secret redacted; `--show-secrets` reveals) |
| `transport resolve --to P --router U` | recipient pubkey → mailbox + shard |

### File transfers (`xfer ...`)

| Command | Does |
|---|---|
| `xfer send --to PEER -f FILE [--mailbox M --shard U] [--chunk-size N]` | encrypt + upload + seal; prints ID + ticket; records the session transfer (`upload` alias) |
| `xfer recv (--ticket B64 \| --transfer H --mailbox M --secret S --manifest B64) -o OUT [--from PEER]` | resume-check, download, verify, decrypt (`download` alias) |
| `xfer resume --transfer H [--ticket B64 --shard U \| --mailbox M --secret S]` | progress + missing ranges, no download |
| `xfer cancel --transfer H --mailbox M [--secret S]` | abort (mailbox owner only; confirms; tickets never cancel) |
| `xfer inspect <ticket>` | decode a ticket offline: who/what/where (secret redacted unless enabled) |
| `xfer list` | transfers created this session |

### Relay diagnostics (`relay ...`)

| Command | Does |
|---|---|
| `relay list` | installed message-capable transports |
| `relay ping [transport]` | start-if-enabled + liveness check |
| `relay info [transport]` | manifest, caps, attachments (never secrets) |

### Messaging and handshake

| Command | Does |
|---|---|
| `message send <peer> <text...> [--ticket T] [--via id] [--mailbox M --shard U]` | encrypt + deliver; `--ticket` appends a transfer ticket as its own line; `--mailbox/--shard` address the recipient explicitly (required on address-shared relays like filerelay) |
| `peer connect <peer> [--via id] [--mailbox M --shard U]` | send a handshake offer (peer answers on poll; poll again to finish) |
| `peer address <peer> --mailbox M --shard U` | record a peer's explicit relay address so offers/answers/messages route without per-command flags |
| `peer list` | peers learned this session (with recorded addresses) |
| `mailbox [thread]` | list threads, or read one (prefixes accepted) |

### Identity, contacts, session

| Command | Does |
|---|---|
| `identity init\|load <id>\|list\|use <id>\|info` | create/select/inspect identities (never prints key material) |
| `contact add\|remove\|list\|info\|note\|rename` | address book |
| `use identity <id>` / `use relay <id>` | select session context |
| `context` | identity, relay, active transfers |
| `alias [name [expansion...]]` | list/define aliases (`xsend`→`xfer send`, `xget`→`xfer recv` built in) |
| `set <json\|show-secrets\|transports-dir> <value>` | session modes |
| `history` / `clear` / `help [command...]` / `switch [name]` / `exit` | shell plumbing |

## File transfer shell workflow

```text
╭─[nextalk:-@-]
╰─❯ use identity alice
╭─[nextalk:alice@-]
╰─❯ use relay filerelay
╭─[nextalk:alice@filerelay]
╰─❯ xfer send --to bob -f ./movie.mp4 --mailbox <A> --shard $R
✓ Transfer created

ID:
abc123...

Ticket:
BgEB...

file "movie.mp4" (88000 bytes, transfer abc123...) via http://127.0.0.1:8080

send the ticket to the recipient inside an E2E message; it carries the download secret
╰─❯ message send bob "Here is the file" --ticket BgEB... --mailbox <B> --shard $R
Message sent to bob....
```

Recipient (any shell, any machine):

```text
╰─❯ transport poll -i bob
[+] Message from alice... (stored in mailbox)
╰─❯ xfer recv BgEB... -o movie.out.mp4
Received 88000 bytes -> movie.out.mp4
```

(`xfer recv` takes a bare ticket positionally. Inspect first with
`xfer inspect BgEB...`. For address-shared relays, record the peer once —
`peer address bob --mailbox <B> --shard $R` — and offers, answers, and
messages route without repeating `--mailbox/--shard`.)

## Scripting

Every command has a non-interactive form: pipe lines into the shell, or use
the one-shot CLI twins. Piped stdin runs each line and exits nonzero if any
line failed; `#` starts a comment:

```bash
printf 'use relay filerelay\nxfer list --json\n' | nextalk shell > out.json
nextalk transport xfer-send filerelay --json -i alice --to bob -f f.bin | process-ticket
```

`--json` guarantees exactly one document per command on stdout; human UI
stays on stderr where `2>/dev/null` can drop it.

## Shell plugins (future transports)

A plugin is a command subtree: call `registry.Register([]string{"mygroup",
"mycommand"}, &shellcmd.Command{...})` from any package imported by the
shell binary — no switch/case to edit, and completion, `help`, aliases, and
suggestions pick it up automatically. External (out-of-process) transports
need no plugin: the generic `transport`/`xfer`/`relay` commands already
drive any installed `.ntx`/`.wasm` module by capability.

## Legacy sub-shells

`switch` (no args) lists the compiled-in transport shells; `switch worker`
enters one with your session identity carried over. They are frozen in
place: bug fixes only, all new surface goes in the unified tree above.
