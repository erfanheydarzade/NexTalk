# Adding a Custom Transport to NexTalk

This guide walks you through creating a new transport backend and wiring it into
both the interactive shell and the CLI. You will never need to touch `root.go`
or `shell.go` — the registry discovers your transport automatically through Go's
`init()` mechanism.

---

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
    API          *core.Engine
    Config       config.Config
    Ctx          context.Context
    ActiveClient *client.Client
    Worker       relay.Relay       // populate this in Init if you need a relay
    Mailbox      map[string][]ChatMessage
    KnownPeers   map[string]bool   // peers seen this session; drives Tab completion
}
```

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