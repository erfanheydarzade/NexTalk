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
}
```

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
    fmt.Println("\nCommands:")
    fmt.Println("  hello          - Say hello")
    fmt.Println("  switch / exit  - Return to main menu")
}
```

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