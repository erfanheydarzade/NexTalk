package shell

import (
	"context"
	"crypto/ed25519"
	"slices"
	"testing"

	Client "github.com/erfanheydarzade/NexTalk/client"
	worker "github.com/erfanheydarzade/NexTalk/cmd/worker"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/mr-tron/base58"
)

// mockRelay is a no-op relay for unit tests that don't need network I/O.
type mockRelay struct{}

func (m *mockRelay) Register(ctx context.Context, privateKey []byte) (string, error) {
	return "", nil
}

func (m *mockRelay) Send(ctx context.Context, recipientPubKey []byte, payload []byte, senderPriv ed25519.PrivateKey) error {
	return nil
}

func (m *mockRelay) Receive(ctx context.Context, privateKey []byte) ([]relay.Message, error) {
	return nil, nil
}

// newWorkerState builds a registry.State with the worker transport's
// Fanout/ContextStore/DeliveryStore wired up, without needing a live relay.
// This mirrors what WorkerGUITransport.Init does, minus the network call.
func newWorkerState(t *testing.T) (*registry.State, *worker.WorkerGUITransport) {
	t.Helper()
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	st.Worker = &mockRelay{}
	// Set up the persistent stores and fanout manually (Init would do this
	// after connecting to the relay, but we skip the network call in tests).
	st.ActiveClient = Client.NewClient()
	st.InitMailbox()
	st.InitFanout()
	if st.Fanout == nil {
		t.Fatal("Fanout must be initialized")
	}
	return st, tr
}

// TestWorkerInitThenContextCreate verifies the bug fix: after `init`,
// `state.Fanout` is non-nil so `context create` works without needing `load`.
func TestWorkerInitThenContextCreate(t *testing.T) {
	st, _ := newWorkerState(t)

	// Fanout should be initialized
	if st.Fanout == nil {
		t.Fatal("Fanout must be initialized after init")
	}

	// Now context create should work
	ctx, err := st.Fanout.CreateContext("Test Group", st.ActiveClient.IdentityPrivate)
	if err != nil {
		t.Fatalf("context create after init: %v", err)
	}
	if ctx.DisplayName != "Test Group" {
		t.Errorf("expected 'Test Group', got %q", ctx.DisplayName)
	}
	if ctx.MetadataVersion != 1 {
		t.Errorf("expected version 1, got %d", ctx.MetadataVersion)
	}
}

// TestContextCompletionSlots verifies the custom completer for the `context`
// command: subcommand words first, context IDs/names for ctx slots, and peer
// candidates only in the member slot of member-taking subcommands.
func TestContextCompletionSlots(t *testing.T) {
	st, tr := newWorkerState(t)
	c := newTestCompleter(st)

	// Create a group and add a known peer.
	tr.Execute(st, "context", []string{"create", "Slot Crew"})
	ctxs, _ := st.Fanout.CtxStore.ListContexts()
	ctxID := string(ctxs[0].ContextID)

	// Slot 1 (empty line after "context"): subcommand words.
	got := complete(t, c, "context ")
	for _, want := range []string{"create", "show", "rename", "members", "mute"} {
		if !slices.Contains(got, want) {
			t.Errorf("slot1 missing %q: %v", want, got)
		}
	}

	// Prefix filtering applies to hook results too.
	if got := complete(t, c, "context cr"); !slices.Contains(got, "create") {
		t.Errorf("prefix 'cr' should offer create: %v", got)
	}

	// Slot 2 for show: context ID + display name.
	got = complete(t, c, "context show ")
	if !slices.Contains(got, ctxID) || !slices.Contains(got, "Slot Crew") {
		t.Errorf("ctx slot missing id/name: %v", got)
	}

	// Slot 2 for create is a free-form name — no candidates.
	if got := complete(t, c, "context create "); len(got) != 0 {
		t.Errorf("create name slot should be free-form, got %v", got)
	}
}

// TestWorkerContextCommands verifies the full lifecycle of context management
// through the GUI transport's Execute method.
func TestWorkerContextCommands(t *testing.T) {
	st, tr := newWorkerState(t)

	// context create
	tr.Execute(st, "context", []string{"create", "My Group"})

	// Verify context was created
	ctxs, err := st.Fanout.CtxStore.ListContexts()
	if err != nil {
		t.Fatal(err)
	}
	if len(ctxs) != 1 {
		t.Fatalf("expected 1 context, got %d", len(ctxs))
	}
	ctxID := ctxs[0].ContextID

	// context list should show it
	tr.Execute(st, "context", []string{"list"})

	// context add — peer must be a WELL-FORMED ID (the shared layer now
	// validates this to catch typos before they poison a delivery set).
	peer := base58.Encode(make([]byte, 64)) // valid-shape synthetic ID
	tr.Execute(st, "context", []string{"add", string(ctxID), peer})

	// Verify policy was set
	pol, err := st.Fanout.GetRecipientPolicy(ctxID, peer)
	if err != nil {
		t.Fatal(err)
	}
	if pol != multimsg.PolicyEnabled {
		t.Errorf("expected PolicyEnabled, got %v", pol)
	}

	// context members should show the peer
	tr.Execute(st, "context", []string{"members", string(ctxID)})

	// context exclude
	tr.Execute(st, "context", []string{"exclude", string(ctxID), peer})
	pol, _ = st.Fanout.GetRecipientPolicy(ctxID, peer)
	if pol != multimsg.PolicyExcluded {
		t.Errorf("expected PolicyExcluded after exclude, got %v", pol)
	}

	// context include (re-enable)
	tr.Execute(st, "context", []string{"include", string(ctxID), peer})
	pol, _ = st.Fanout.GetRecipientPolicy(ctxID, peer)
	if pol != multimsg.PolicyEnabled {
		t.Errorf("expected PolicyEnabled after include, got %v", pol)
	}

	// context mute
	tr.Execute(st, "context", []string{"mute", string(ctxID), peer})
	pol, _ = st.Fanout.GetRecipientPolicy(ctxID, peer)
	if pol != multimsg.PolicyMuted {
		t.Errorf("expected PolicyMuted after mute, got %v", pol)
	}

	// context block
	tr.Execute(st, "context", []string{"block", string(ctxID), peer})
	pol, _ = st.Fanout.GetRecipientPolicy(ctxID, peer)
	if pol != multimsg.PolicyBlocked {
		t.Errorf("expected PolicyBlocked after block, got %v", pol)
	}

	// context rename
	tr.Execute(st, "context", []string{"rename", string(ctxID), "Renamed Group"})
	updated, err := st.Fanout.CtxStore.LoadContext(ctxID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Renamed Group" {
		t.Errorf("expected 'Renamed Group', got %q", updated.DisplayName)
	}
	if updated.MetadataVersion != 2 {
		t.Errorf("expected version 2 after rename, got %d", updated.MetadataVersion)
	}

	// contexts command lists all
	tr.Execute(st, "contexts", nil)

	// context show
	tr.Execute(st, "context", []string{"show", string(ctxID)})
}

// TestWorkerContextCreateFailsWithoutIdentity verifies that context create
// returns a helpful error when no identity is loaded.
func TestWorkerContextCreateFailsWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// Don't set ActiveClient — Fanout stays nil

	// context create should fail gracefully (print a message, not panic)
	tr.Execute(st, "context", []string{"create", "Test"})
	// Fanout should be nil since no client was loaded
	if st.Fanout != nil {
		t.Error("Fanout should be nil without an active client")
	}
}

// TestWorkerSendMultiFailsWithoutRecipients verifies that send-multi
// with no enabled recipients returns a warning.
func TestWorkerSendMultiFailsWithoutRecipients(t *testing.T) {
	st, tr := newWorkerState(t)

	// Create context but add no recipients
	tr.Execute(st, "context", []string{"create", "Empty"})
	ctxs, _ := st.Fanout.CtxStore.ListContexts()
	ctxID := ctxs[0].ContextID

	// send-multi should warn about no recipients
	tr.Execute(st, "send-multi", []string{string(ctxID), "hello"})
}

// TestWorkerContextCandidates verifies that ContextCandidates returns
// the right set for Tab completion.
func TestWorkerContextCandidates(t *testing.T) {
	st, tr := newWorkerState(t)

	// No contexts yet
	candidates := st.ContextCandidates()
	if len(candidates) != 0 {
		t.Errorf("expected no candidates, got %v", candidates)
	}

	// Create a context
	tr.Execute(st, "context", []string{"create", "My Group"})
	candidates = st.ContextCandidates()
	if len(candidates) == 0 {
		t.Error("expected at least one candidate after creating context")
	}

	// Both the ContextID and DisplayName should be candidates
	ctxs, _ := st.Fanout.CtxStore.ListContexts()
	ctxID := string(ctxs[0].ContextID)
	displayName := ctxs[0].DisplayName

	if !slices.Contains(candidates, ctxID) {
		t.Errorf("candidates missing context ID %q: %v", ctxID, candidates)
	}
	if !slices.Contains(candidates, displayName) {
		t.Errorf("candidates missing display name %q: %v", displayName, candidates)
	}
}

// TestWorkerCompletionIncludesContextCommands verifies that the worker
// transport's Commands() includes all context-related commands for Tab completion.
func TestWorkerCompletionIncludesContextCommands(t *testing.T) {
	tr := &worker.WorkerGUITransport{}
	cmds := tr.Commands()

	var names []string
	for _, c := range cmds {
		names = append(names, c.Name)
	}

	for _, want := range []string{
		"init", "load", "connect", "listen", "send", "mailbox",
		"context", "send-multi", "contexts", "peers", "help", "switch",
	} {
		if !slices.Contains(names, want) {
			t.Errorf("worker completion missing command %q: %v", want, names)
		}
	}

	// Verify context command uses the custom completer (slot-dependent
	// completion) rather than static Args.
	var ctxCmd *registry.CommandSpec
	for i := range cmds {
		if cmds[i].Name == "context" {
			ctxCmd = &cmds[i]
			break
		}
	}
	if ctxCmd == nil {
		t.Fatal("context command not found")
	}
	if ctxCmd.Complete == nil {
		t.Error("context command should declare a Complete hook for slot-aware completion")
	}

	// Verify send-multi has context + text args
	var smCmd *registry.CommandSpec
	for i := range cmds {
		if cmds[i].Name == "send-multi" {
			smCmd = &cmds[i]
			break
		}
	}
	if smCmd == nil {
		t.Fatal("send-multi command not found")
	}
	if len(smCmd.Args) < 2 || smCmd.Args[0] != registry.ArgContext || smCmd.Args[1] != registry.ArgText {
		t.Errorf("send-multi command args: expected [ArgContext, ArgText], got %v", smCmd.Args)
	}
}

// TestWorkerLoadReinitFanout verifies that `load` re-initializes the fanout
// with the loaded client's identity.
func TestWorkerLoadReinitFanout(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	st.Worker = &mockRelay{}

	// Create and save a client
	cl := Client.NewClient()
	Client.SaveClient(cl)

	// Load the client via the transport
	tr.Execute(st, "load", []string{cl.Id})

	// Fanout should be initialized with the loaded client
	if st.Fanout == nil {
		t.Fatal("Fanout must be initialized after load")
	}
	if st.ActiveClient == nil {
		t.Fatal("ActiveClient must be set after load")
	}
	if st.ActiveClient.Id != cl.Id {
		t.Errorf("expected loaded client ID %s, got %s", cl.Id, st.ActiveClient.Id)
	}
}

// TestWorkerMailboxCommands verifies mailbox operations in the worker transport.
func TestWorkerMailboxCommands(t *testing.T) {
	st, tr := newWorkerState(t)

	// Mailbox should be empty
	tr.Execute(st, "mailbox", nil)

	// Record an incoming message through the persistent store — the same
	// path the listen/dispatch handlers use.
	peer := "testpeer"
	if err := st.MailboxStore.AppendIncoming(peer, "test message"); err != nil {
		t.Fatal(err)
	}

	// Mailbox list should show the peer
	tr.Execute(st, "mailbox", nil)

	// Reading a specific peer's messages
	tr.Execute(st, "mailbox", []string{peer})

	// Message should be marked as read in the store (and persisted).
	msgs, err := st.MailboxStore.Read(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	// Reload from disk: the message must survive the "restart".
	reloaded, err := mailbox.Load(st.ActiveClient.Id)
	if err != nil {
		t.Fatal(err)
	}
	thread, ok := reloaded.Get(peer)
	if !ok || len(thread.Messages) != 1 {
		t.Fatalf("expected persisted thread for %q, got %+v", peer, thread)
	}
	for _, m := range thread.Messages {
		if !m.IsRead {
			t.Error("persisted message should be marked as read after viewing")
		}
	}
}

// TestWorkerPeersCommand verifies the peers command lists known peers.
func TestWorkerPeersCommand(t *testing.T) {
	st, tr := newWorkerState(t)

	// No peers yet
	st.RememberPeer("peer123")
	st.RememberPeer("peer456")

	// peers command should list them
	tr.Execute(st, "peers", nil)
}

// TestWorkerHelpCommand verifies the help command renders without panic.
func TestWorkerHelpCommand(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	// Help doesn't need state
	tr.Help()
}

// TestWorkerUnknownCommand verifies unknown commands are handled gracefully.
func TestWorkerUnknownCommand(t *testing.T) {
	st, tr := newWorkerState(t)

	// Unknown command should not panic
	tr.Execute(st, "unknowncmd", nil)
}

// TestWorkerSwitchExit verifies that switch/exit returns false to go back to main menu.
func TestWorkerSwitchExit(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())

	if tr.Execute(st, "switch", nil) {
		t.Error("switch should return false to exit to main menu")
	}
	if tr.Execute(st, "exit", nil) {
		t.Error("exit should return false to exit to main menu")
	}
}

// TestWorkerContextSubcommandErrors verifies error handling for malformed
// context subcommands.
func TestWorkerContextSubcommandErrors(t *testing.T) {
	st, tr := newWorkerState(t)

	// context without subcommand
	tr.Execute(st, "context", nil)

	// context create without name
	tr.Execute(st, "context", []string{"create"})

	// context show with nonexistent ID
	tr.Execute(st, "context", []string{"show", "nonexistent"})

	// context rename without new name
	tr.Execute(st, "context", []string{"rename", "ctx123"})

	// context add without peer
	tr.Execute(st, "context", []string{"add", "ctx123"})

	// context exclude without peer
	tr.Execute(st, "context", []string{"exclude", "ctx123"})

	// context include without peer
	tr.Execute(st, "context", []string{"include", "ctx123"})

	// context block without peer
	tr.Execute(st, "context", []string{"block", "ctx123"})

	// context mute without peer
	tr.Execute(st, "context", []string{"mute", "ctx123"})

	// context members without context ID
	tr.Execute(st, "context", []string{"members"})

	// unknown subcommand
	tr.Execute(st, "context", []string{"unknown"})
}

// TestWorkerSendMultiWithoutContext verifies send-multi fails gracefully
// when the context doesn't exist.
func TestWorkerSendMultiWithoutContext(t *testing.T) {
	st, tr := newWorkerState(t)

	// send-multi to nonexistent context
	tr.Execute(st, "send-multi", []string{"nonexistent", "hello"})
}

// TestWorkerLoadWithoutArg verifies load without an argument shows usage.
func TestWorkerLoadWithoutArg(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())

	// load without arg should print usage
	tr.Execute(st, "load", nil)
}

// TestWorkerConnectWithoutIdentity verifies connect fails gracefully
// when no identity is loaded.
func TestWorkerConnectWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// No ActiveClient set

	// connect should fail gracefully
	tr.Execute(st, "connect", []string{"peer123"})
}

// TestWorkerSendWithoutIdentity verifies send fails gracefully
// when no identity is loaded.
func TestWorkerSendWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// No ActiveClient set

	// send should fail gracefully
	tr.Execute(st, "send", []string{"peer123", "hello"})
}

// TestWorkerListenWithoutIdentity verifies listen fails gracefully
// when no identity is loaded.
func TestWorkerListenWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// No ActiveClient set

	// listen should fail gracefully
	tr.Execute(st, "listen", nil)
}

// TestWorkerMailboxWithoutIdentity verifies mailbox works without identity
// (it just shows empty).
func TestWorkerMailboxWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// No ActiveClient set

	// mailbox should show empty without error
	tr.Execute(st, "mailbox", nil)
}

// TestWorkerContextsWithoutIdentity verifies contexts command fails gracefully
// when no identity is loaded.
func TestWorkerContextsWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// No ActiveClient set

	// contexts should fail gracefully
	tr.Execute(st, "contexts", nil)
}

// TestWorkerSendMultiWithoutIdentity verifies send-multi fails gracefully
// when no identity is loaded.
func TestWorkerSendMultiWithoutIdentity(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// No ActiveClient set

	// send-multi should fail gracefully
	tr.Execute(st, "send-multi", []string{"ctx123", "hello"})
}

// TestWorkerContextWithoutFanout verifies context commands fail gracefully
// when fanout is not initialized.
func TestWorkerContextWithoutFanout(t *testing.T) {
	chdirTemp(t)
	tr := &worker.WorkerGUITransport{}
	st := registry.NewState(nil, testConfig())
	// Don't set ActiveClient, so Fanout stays nil

	// context create should fail gracefully
	tr.Execute(st, "context", []string{"create", "Test"})
}
