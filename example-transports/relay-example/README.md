# relay-example — third-party transport template

A complete, working NexTalk transport in one ~400-line Go program. Copy this
directory and make it yours.

## What it is

Filesystem-backed local transport (`message` capability, no permissions).
Mailbox = `hex(sha256(ed25519_pub)[:16])`. Send appends an opaque frame file;
poll drains it (burn-after-read). No network, no keys, no crypto — frames are
opaque bytes the core encrypted.

## Build your own (template walkthrough)

1. Copy this directory to `my-transport/`.
2. Edit `manifest.json`: new `id`, `name`, `version`. Keep `api_version: "1"`.
   Declare only capabilities you implement; only permissions you need.
3. Implement the 8 ops in `main.go` (`dispatchOp`): initialize, capabilities,
   start/stop, send, attach, detach, poll, status. Keep `rpc.go` byte
   layout identical (schemas 100–113 subset of the 100–126 registry; op-0
   errors on failure) — the golden test pins it. (`binary-transfer` ops
   9–15 exist for file-capable transports; message-only transports never
   receive them — the core gates with `RequiresFile`.)
4. Keep the trust rule: frames are opaque; never add key fields to the RPC.
5. Build, package, install — no NexTalk rebuild, ever.

## Build

```bash
go build -o relay-example .            # entry matches manifest.json
# Windows: go build -o relay-example.exe .  (and set manifest "entry" to relay-example.exe)
go test ./...
```

## Package (.ntx = zip, manifest.json at root)

```bash
zip relay-example.ntx manifest.json relay-example
# Windows PowerShell:
# Compress-Archive -Path manifest.json,relay-example.exe -DestinationPath relay-example.ntx
```

## Install & use (no rebuild)

```bash
nextalk transport install relay-example.ntx
nextalk transport enable relay-example
nextalk transport list
# relay-example  enabled   v1.0.0      caps=[message]
```

## Two-user local scenario (Alice ↔ Bob, same machine)

```bash
# Identities (one dir per user so <id>.json files don't collide)
mkdir alice bob && cd alice && nextalk offline init          # -> ALICE
cd ../bob && nextalk offline init                            # -> BOB

# Handshake once via files (transport-agnostic envelopes)
cd ../alice && nextalk offline offer -i ALICE -r BOB -o offer.bin
cd ../bob && nextalk offline accept -i BOB -f ../alice/offer.bin -o answer.bin
cd ../alice && nextalk offline finish -i ALICE -f ../bob/answer.bin
# (Bob's session was established by accept; Alice's by finish.)

# Mailbox ids for this transport (ed pub = first 32B of the peer ID)
relay-example mailbox --pub <ALICE_ED_HEX>   # -> AMBOX
relay-example mailbox --pub <BOB_ED_HEX>     # -> BMBOX

# Each side attaches its OWN mailbox with its OWN bearer secret
# (senders need no secret; only polling is authenticated).
cd ../alice
nextalk transport attach relay-example --mailbox AMBOX --secret <alice-64hex> --shard local
cd ../bob
nextalk transport attach relay-example --mailbox BMBOX --secret <bob-64hex> --shard local

# Alice encrypts (core crypto), frames it, and sends it (transport courier)
cd ../alice
nextalk offline encrypt -i ALICE -r BOB -m "hello bob" -o msg.bin
relay-example wrap --type 3 -f msg.bin > frame.bin
nextalk transport send-frame relay-example --to BOB -f frame.bin
cd ../bob && nextalk transport poll relay-example -i BOB
# [+] Message from <ALICE> (utf-8) — stored in mailbox
```

`send-frame` takes any full layer-1 frame file (`[type][payload]`);
`poll` runs it through the same shared dispatch as `worker listen`.
