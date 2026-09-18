# Adding a Transport to NexTalk

There are **two** ways to add a transport. Pick one:

| | **A. External module (recommended)** | **B. Compiled-in transport** |
|---|---|---|
| Who | Third-party developers, anyone | Core team only |
| Rebuild NexTalk? | **Never** — ship a `.ntx` file | Yes — new package + blank import |
| Isolation | OS process or WASM sandbox | In-process (full trust) |
| Sees user keys? | **Impossible** — the RPC has no key fields | Yes (same process) |
| Template | `example-transports/relay-example/` | Steps 1–5 below |

Start with A unless your transport must live inside the binary. The runtime
system is specified in [`transport-runtime.md`](transport-runtime.md) and
exercised end-to-end in [`real-scenario.md`](real-scenario.md).

---

# Part A — External transport module (no rebuild)

## A.1 Copy the template

`example-transports/relay-example/` is a complete, working transport in its
own Go module: filesystem queue, `message` capability, golden wire-compat
test. Copy the directory and make it yours — its
[`README.md`](../example-transports/relay-example/README.md) walks through
build, package, install, and a two-user chat scenario.

The template works in any language: the contract is bytes on stdio (or WASM
function calls), not Go APIs.

## A.2 Write `manifest.json`

```json
{
  "id": "my-transport",
  "name": "My Transport",
  "version": "1.0.0",
  "api_version": "1",
  "entry": "my-transport",
  "capabilities": ["message"],
  "permissions": ["network"]
}
```

Rules (enforced at install — fail closed):

- `id`: `^[a-z0-9][a-z0-9-]{0,63}$`; `entry`: bare file name, no paths.
- `api_version` must be `"1"` (the only version the core speaks).
- `capabilities` ⊆ `message`, `binary-transfer`, `presence`,
  `local-network`, `p2p`. Declare only what you implement.
- `permissions` ⊆ `network`, `storage`. There is no `identity-keys`
  permission and there never will be — see the trust rule below.
- `.wasm` entries run sandboxed under wazero (see A.5); anything else spawns
  as an external process.

## A.3 Implement the ops

Transport API v1 (`api_version: "1"`), stdio framing `[len BE32][NanoPack
body]`, schema 100 `Envelope{op, req_id, payload}`. Full table with schema
IDs: [`transport-runtime.md`](transport-runtime.md#5-transport-api-v1-apiversion-1).

Message-only transports implement 8 ops — `initialize`, `capabilities`,
`start`/`stop`, `send`, `attach`, `detach`, `poll`, `status` — and answer
anything else with op 0 + `SchemaError`. `binary-transfer` adds
register/resolve plus `xfer-create/put/resume/get/complete` (schemas
115–126). Keep the schema IDs byte-identical; the golden tests on both
sides pin them.

## A.4 The trust rule (non-negotiable)

Frames are opaque `[type byte][nanopack payload]` bytes the core encrypted.
Your transport:

- carries frames, recipient public keys / explicit mailbox addresses,
  per-mailbox `read_secret` bearers, and URLs — and **nothing else**;
- never adds key fields to the RPC (reviewers check this first);
- authenticates mailbox reads with the bearer the core hands it per call;
- signs its own server requests (if any) with its **own** courier key, like
  the FileRelay bridge does — the true sender lives inside the E2E frame.

## A.5 Native or WASM

- **Native** (`entry: "my-transport"`): any executable speaking the stdio
  RPC. Use it when you need sockets, the filesystem, or existing libraries.
- **WASM** (`entry: "queue.wasm"`): implements the function-call ABI in
  [`transport-runtime.md`](transport-runtime.md#10-wasm-transports)
  (`ntx_init/caps/start/stop/send/attach/detach/poll/status` over linear
  memory). No WASI, no sockets, no filesystem — queue-model transports fit;
  socket transports must use the process model. The hand-assembled module in
  `internal/transport/wasm_*_test.go` is the ABI reference implementation.

## A.6 Package, install, verify

`.ntx` = zip with `manifest.json` at root plus the entry binary:

```bash
zip my-transport.ntx manifest.json my-transport
nextalk transport install my-transport.ntx     # validates, hash-pins, disabled by default
nextalk transport enable my-transport
nextalk transport list
# my-transport  enabled   v1.0.0      caps=[message]
```

Then exercise it for real: attach a mailbox, `send-frame` an encrypted
frame, `poll` it back through shared dispatch — exactly as
[`real-scenario.md`](real-scenario.md) scenarios A–C do.

---

# Part B — Compiled-in transport (core team)

Use this only when the transport must ship inside the `nextalk` binary
(`worker`, `proxy`, `offline` live here). You will touch the build, but you
will never need to touch `root.go` or `shell.go` — the registry discovers
your transport automatically through Go's `init()` mechanism.

## How the registry works

```
cmd/transports/state.go   ← blank-import shim that triggers every init()
      │
      ├── cmd/offline/register.go   init() → registry.Register(...)
      ├── cmd/worker/register.go    init() → registry.Register(...)
      └── cmd/proxy/register.go     init() → registry.Register(...)
                                              │
                              internal/registry/registry.go
                              ┌────────────────────────────┐
                              │  []Entry  (sorted by       │
                              │  MenuOrder)                │
                              │                            │
                              │  GUITransports() ──► shell │
                              │  CLITransports() ──► root  │
                              └────────────────────────────┘
```

Each `Entry` carries two optional faces:

| Field | Interface | Used by |
|-------|-----------|---------|
| `GUI` | `registry.GUITransport` | Interactive shell (`nextalk shell`) |
| `CLI` | `registry.CLITransport` | Cobra subcommands (`nextalk <name> ...`) |

Either face can be `nil` if your transport only needs one of them.

**Prefer the runtime system**: every transport built this way is trusted
with the user's private keys (same process) and can only ship in a NexTalk
release. If an external module can do the job, build that instead (Part A).

---

## Step 1 — Create the package

```
cmd/
└── mytransport/
    ├── command.go    ← cobra subcommands (CLI face)
    └── register.go   ← self-registration + GUI face
```

You can use any package name. The directory name is just a convention.

---

## Step 2 — Implement the CLI face (optional)

`cmd/mytransport/command.go`

```go
package mytransport

import (
    "github.com/erfanheydarzade/NexTalk/core"
    "github.com/erfanheydarzade/NexTalk/internal/config"
    "github.com/spf13/cobra"
)

// Register mounts your cobra subcommands onto parent.
// Called by the registry; you do not call this directly.
func Register(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
    cmd := &cobra.Command{
        Use:   "mytransport",
        Short: "My custom transport",
    }
    cmd.AddCommand(runCmd(engine, cfg))
    parent.AddCommand(cmd)
}

func runCmd(engine *core.Engine, cfg config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "run",
        Short: "Start my transport",
        Run: func(cmd *cobra.Command, args []string) {
            // your runtime logic here
        },
    }
}
```

---

## Step 3 — Implement the GUI face (optional)

The GUI face is what the interactive shell (`nextalk shell`) calls.
Implement the `registry.GUITransport` interface:

```go
// GUITransport is defined in internal/registry/registry.go
type GUITransport interface {
    Name()      string   // short lowercase ID, shown in the sub-shell prompt
    MenuLabel() string   // line printed in the main menu
    Init(*State) error   // called once when the user picks this transport
    Execute(*State, cmd string, args []string) bool // return false → back to menu
    Help()               // print command reference
}
```

`registry.State` (defined in `internal/registry/state.go`) holds everything
your commands might need:

```go
type State struct {
    API           *core.Engine
    Config        config.Config
    Ctx           context.Context
    ActiveClient  *Client.Client
    Worker        relay.Relay      // populate this in Init if you need a relay
    MailboxStore  *mailbox.Store   // persistent per-identity history
    KnownPeers    map[string]bool  // peers seen this session; drives Tab completion
    ContextStore  multimsg.ContextStore
    DeliveryStore multimsg.DeliveryStore
    Fanout        *multimsg.Fanout
}
```

> Prefer receiving through the shared path: poll your backend for raw
> layer-1 frames and feed each one to `dispatch.DispatchFrame` (package
> `internal/dispatch`) instead of reimplementing offer/answer/message/group
> handling. That is the same code `worker listen` and `transport poll` run —
> one handshake implementation everywhere. Replies go out through the
> `dispatch.Sender` callback you bind to your own send.

`State` also carries the helpers the shell's Tab completion relies on:

| Method | Purpose |
|--------|---------|
| `RememberPeer(id)` | Record a peer ID so it becomes Tab-completable immediately |
| `SyncPeersFromClient()` | Record every session persisted in the loaded `<id>.json` |
| `ResolvePeer(input)` | Expand a contact alias or unique ID prefix to a full peer ID |
| `PeerCandidates()` | All completable peer IDs and contact aliases |
| `IdentityCandidates()` | Local `<id>.json` profiles, for `load <id>` |

A minimal but complete implementation:

```go
type MyGUITransport struct{}

func (t *MyGUITransport) Name()      string { return "mytransport" }
func (t *MyGUITransport) MenuLabel() string { return "4. My Transport  (Custom Backend)" }

func (t *MyGUITransport) Init(state *registry.State) error {
    fmt.Println("\n  ❖ My Transport ❖\n")
    // initialise anything you need in state here, e.g.:
    // state.Worker = myrelay.New(state.Config.MyURL)
    return nil
}

func (t *MyGUITransport) Execute(state *registry.State, cmd string, args []string) bool {
    switch cmd {

    case "hello":
        fmt.Println("  Hello from my transport!")

    case "help":
        t.Help()

    case "switch", "exit":
        return false // tells the shell to go back to the main menu

    default:
        fmt.Printf("  Unknown command %q. Type 'help'.\n", cmd)
    }
    return true // stay in the sub-shell
}

func (t *MyGUITransport) Help() {
    // Render from the same specs that drive Tab completion (see Step 3b) so
    // help and completion can never disagree about what exists.
    registry.RenderHelp(t.Commands())
}
```

---

## Step 3b — Declare your commands for Tab completion

Implement the optional `registry.CompletionProvider` interface. This is what
makes your commands and their arguments complete with `Tab`:

```go
// CompletionProvider is defined in internal/registry/completion.go
type CompletionProvider interface {
    Commands() []CommandSpec
}
```

Each `CommandSpec` names a command and declares the *kind* of each positional
argument, which is what tells the completer where to offer peer IDs:

```go
func (t *MyGUITransport) Commands() []registry.CommandSpec {
    specs := []registry.CommandSpec{
        {
            Name:  "load",
            Args:  []registry.ArgKind{registry.ArgIdentity}, // ./<id>.json files
            Usage: "load <id>",
            Help:  "Load an existing local identity",
        },
        {
            Name:     "send",
            Aliases:  []string{"encrypt"},                // both words complete
            Args:     []registry.ArgKind{registry.ArgPeer}, // peers + contacts
            Variadic: registry.ArgText,                    // message body: no completion
            Usage:    "send <peer> <msg>",
            Help:     "Encrypt and dispatch a message",
        },
    }
    // Appends help/switch/exit so they never have to be redeclared.
    return append(specs, registry.BaseCommands()...)
}
```

`ArgKind` values:

| Kind | Completes with |
|------|----------------|
| `ArgPeer` | Known peer IDs plus contact aliases |
| `ArgIdentity` | `<id>.json` profiles in the current directory |
| `ArgContact` | Contact aliases only |
| `ArgText` | Nothing (free-form text: messages, pasted JSON) |

`Args` covers the fixed leading arguments; `Variadic` applies to every argument
after them.

Two rules keep completion useful:

1. **Call `state.RememberPeer(id)` as soon as you learn a peer ID** — after
   sending an offer, accepting one, finishing a handshake, or decrypting a
   message. Waiting for a mailbox entry means the peer stays uncompletable and
   the user has to retype a 44-character base58 ID.
2. **Resolve peer arguments with `state.ResolvePeer(args[0])`** instead of using
   `args[0]` directly, so contact aliases and unique ID prefixes work. It
   returns an error for an ambiguous prefix rather than guessing — print it and
   return `true`.

Skipping `Commands()` entirely is allowed: your transport still works, it just
falls back to completing only `help`, `switch` and `exit`.

---

## Step 4 — Self-register in `init()`

`cmd/mytransport/register.go`

```go
package mytransport

import "github.com/erfanheydarzade/NexTalk/internal/registry"

func init() {
    registry.Register(registry.Entry{
        GUI:       &MyGUITransport{},   // nil if you have no interactive mode
        CLI:       &myCLITransport{},   // nil if you have no cobra commands
        MenuOrder: 4,                   // controls position in the main menu
    })
}

// myCLITransport is a thin wrapper that satisfies registry.CLITransport.
type myCLITransport struct{}

func (m *myCLITransport) RegisterCLI(
    parent *cobra.Command,
    engine *core.Engine,
    cfg    config.Config,
) {
    Register(parent, engine, cfg) // delegates to command.go
}
```

`MenuOrder` values used by the built-in transports:

| Transport | MenuOrder |
|-----------|-----------|
| offline   | 1         |
| worker    | 2         |
| proxy     | 3         |

Pick a number that places your transport where you want it in the menu.
The registry sorts entries automatically — gaps are fine.

---

## Step 5 — Add the package to the shim

Open `cmd/transports/state.go` and add a blank import for your package:

```go
package transports

import (
    _ "github.com/erfanheydarzade/NexTalk/cmd/mytransport" // ← add this line
    _ "github.com/erfanheydarzade/NexTalk/cmd/offline"
    _ "github.com/erfanheydarzade/NexTalk/cmd/proxy"
    _ "github.com/erfanheydarzade/NexTalk/cmd/worker"
)
```

This is the **only file outside your own package** you need to touch.
The blank import causes Go to run your `init()`, which calls `registry.Register`,
which makes both `GUITransports()` and `CLITransports()` return your entry.

---

## Verification

Build and run the shell:

```bash
go build ./... && ./nextalk shell
```

You should see your transport listed in the main menu. Select it and type
`help` to confirm your commands are reachable.

Check the CLI side:

```bash
./nextalk mytransport --help
```

---

## Complete file checklist

```
cmd/mytransport/
├── command.go    defines Register() + cobra subcommands
└── register.go   init() calls registry.Register; defines GUI/CLI transport types

cmd/transports/state.go   add one blank import line
```

That's all. No other file needs editing.

---

## Common mistakes

**Duplicate `Name()`** — the registry panics at startup if two `GUITransport`
implementations return the same string from `Name()`. Pick a unique name.

**Forgetting the shim** — if you skip the blank import in
`cmd/transports/state.go`, your `init()` never runs and the transport is
silently absent from the menu.

**Returning `true` from `Execute` on `"exit"`** — always return `false` for
`"switch"` and `"exit"` so the shell loop can return the user to the main menu.

**Storing state outside `registry.State`** — avoid instance fields on your
`GUITransport` struct for things that should survive across sub-shell entries
(like the active identity or mailbox). Put those in `registry.State` instead;
that value is shared across all transports in a single `nextalk shell` session.

**Reimplementing receive dispatch** — don't copy the offer/answer/message
switch from the old worker code. Call `dispatch.DispatchFrame` with a
`Sender` bound to your backend; group handling, dedupe, mailbox persistence,
and event shapes stay identical for every transport.

---

## Wiring the same transport into the WASM build

The `internal/registry` auto-discovery above is CLI/shell-only — see
[`wasm.md`](wasm.md#why-the-relay-just-works-in-wasm) for why: a browser tab has no
terminal REPL to offer a transport menu in, and no `init()`-blank-import
step, since `cmd/nextalk-wasm/main.go` never imports `cmd/transports`.
Making your transport available from JS is a separate, smaller step: add
one file to `internal/wasmbridge/` and mount it in `register.go`, the
same pattern `relay.go` (the worker transport) already follows.

1. **Add `internal/wasmbridge/<name>.go`.** Model it on `relay.go`:
   construct your transport's adapter, hold it on `internal/wasmbridge`'s
   shared `state` (the wasm analogue of `client.Client`), and expose one
   `js.Func` per operation. Reuse the *same* transport-side code the CLI
   uses (e.g. `internal/relay/<name>`) rather than reimplementing
   protocol logic in the bridge — that's the whole point of the split
   `wasm.md` describes between `internal/relay/worker.Adapter` (shared)
   and `internal/wasmbridge/relay.go` (browser-only plumbing around it).
   If your transport's `Send`/`Receive` doesn't yet satisfy
   `relay.Relay` polymorphically (see the proxy-transport gap noted in
   `wasm.md`), fix that first — the bridge should call through the same
   interface the worker transport does, not a one-off.

2. **Mount your functions in `register.go`.** This file is "the one
   place that ever mounts a new call onto the `NexTalk` global" — the
   wasm build's equivalent of `cmd/root.go` mounting CLI command groups.
   Add your namespace there, e.g.:

    ```go
    // internal/wasmbridge/register.go
    func Register() {
        // ... existing identity / handshake / message / relay / contacts ...
        registerMyTransport() // defined in your new my_transport.go
    }
    ```

3. **No shim, no `init()` magic.** Unlike the CLI registry, there's
   nothing else to touch — no blank import, no `MenuOrder`. `main.go`
   stays protocol-free either way.

4. **Rebuild and re-check the JS surface.**

    ```bash
    ./cmd/nextalk-wasm/build.sh
    python3 -m http.server 8000   # see wasm.md — file:// will not work
    ```

    Open `http://localhost:8000/web/`, and in the devtools console confirm
    your new `NexTalk.<yourNamespace>.*` functions exist and return the
    `{ ... } | { error: "..." }` shape every other bridge call uses.

5. **Document the addition.** Add your new calls to the "JS API" table in
   `wasm.md`, next to `NexTalk.relay.*`, so the two docs stay in sync the
   same way `register.go` and `cmd/root.go` mirror each other for the CLI.

If your transport has no meaningful browser story (e.g. it depends on a
local filesystem layout offline mode doesn't need), it's fine to leave it
CLI/shell-only and skip this section entirely — nothing about the
`internal/registry` steps above requires a wasm counterpart.
