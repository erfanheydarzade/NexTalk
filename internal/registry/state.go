// internal/registry/state.go
//
// State is the shared runtime context passed into every GUITransport method.
// Keeping it here (rather than in cmd/shell) breaks the import cycle that
// would arise if transport packages needed to import cmd/shell.
package registry

import (
	"context"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// State holds everything a GUITransport might need across commands within one
// sub-shell session. Fields are intentionally exported so transports can read
// and write them directly — the registry package owns the type but imposes no
// access restrictions on it.
type State struct {
	API    *core.Engine
	Config config.Config
	Ctx    context.Context

	// ActiveClient is whichever identity is currently loaded or initialised.
	ActiveClient *Client.Client

	// Worker is populated by WorkerTransport.Init; nil for other transports.
	Worker relay.Relay

	// MailboxStore persists conversations (<id>.mailbox.json) so messages
	// survive shell restarts and are shared with one-shot CLI commands
	// (`worker listen`, `worker mailbox`). It is bound to ActiveClient by
	// InitMailbox; nil until an identity is initialised or loaded.
	MailboxStore *mailbox.Store

	// KnownPeers is the set of peer IDs this session has seen, from any
	// direction: a peer we sent an offer to, a peer whose offer we accepted,
	// a peer whose answer completed our handshake, or a peer who messaged us.
	//
	// It exists because the mailbox alone is not enough for Tab completion —
	// threads only appear once a *message* is exchanged, so a peer ID typed
	// into `connect` (or received via `listen`) would otherwise have to be
	// retyped in full for every later command. Peers are recorded via
	// State.RememberPeer; see peers.go.
	KnownPeers map[string]bool

	// ContextStore provides persistence for multi-message contexts (groups).
	ContextStore multimsg.ContextStore

	// DeliveryStore provides persistence for multi-message deliveries.
	DeliveryStore multimsg.DeliveryStore

	// Fanout provides the multi-message fan-out logic.
	Fanout *multimsg.Fanout
}

// NewState returns an empty State ready for use by RunGUI.
func NewState(api *core.Engine, cfg config.Config) *State {
	return &State{
		API:           api,
		Config:        cfg,
		Ctx:           context.Background(),
		KnownPeers:    make(map[string]bool),
		ContextStore:  multimsg.NewMemoryContextStore(),
		DeliveryStore: multimsg.NewMemoryDeliveryStore(),
	}
}

// InitMailbox binds the persistent mailbox store to the active client.
// Call after init or load. When no identity is active it clears any stale
// binding from a previously loaded identity.
func (s *State) InitMailbox() {
	if s.ActiveClient == nil {
		s.MailboxStore = nil
		return
	}
	st, err := mailbox.Load(s.ActiveClient.Id)
	if err != nil {
		// A corrupt mailbox file must never lock the user out of their keys;
		// degrade to nil and let callers report "mailbox unavailable".
		s.MailboxStore = nil
		return
	}
	s.MailboxStore = st
}

// InitFanout initializes the multi-message fanout for the active client.
// Call this after init or load to enable multi-message commands.
//
// Contexts, policies and deliveries are persisted per identity
// (<id>.contexts.json / <id>.policies.json / <id>.deliveries.json) so groups
// created in one session survive restarts. Memory stores remain the fallback
// for identities without a writable working directory (wasm).
func (s *State) InitFanout() {
	if s.ActiveClient == nil {
		return
	}
	ctxStore, deliveryStore, err := multimsg.OpenIdentityStores(s.ActiveClient.Id)
	if err != nil {
		// A missing/unreadable store must never lock the user out; fall back
		// to in-memory (also covers sandboxed targets like wasm).
		ctxStore = multimsg.NewMemoryContextStore()
		deliveryStore = multimsg.NewMemoryDeliveryStore()
	}
	s.ContextStore = ctxStore
	s.DeliveryStore = deliveryStore
	s.Fanout = multimsg.NewFanout(s.ActiveClient, s.Worker, s.ContextStore, s.DeliveryStore, multimsg.DefaultFanoutConfig())
}

// ThreadCandidates returns everything `mailbox` accepts: peer IDs/aliases
// plus every group thread's display name and context ID.
func (s *State) ThreadCandidates() []string {
	set := make(map[string]bool)
	for _, p := range s.PeerCandidates() {
		set[p] = true
	}
	if s.MailboxStore != nil {
		for _, t := range s.MailboxStore.List() {
			if mailbox.IsGroupKey(t.Key) {
				set[t.Key] = true
				if t.Title != "" {
					set[t.Title] = true
				}
			}
		}
	}
	return sortedKeys(set)
}

// ContextCandidates returns the context IDs that `context` subcommands accept.
// These come from the ContextStore populated during the session.
func (s *State) ContextCandidates() []string {
	if s.Fanout == nil || s.Fanout.CtxStore == nil {
		return nil
	}
	ctxs, err := s.Fanout.CtxStore.ListContexts()
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(ctxs))
	for _, c := range ctxs {
		if c != nil {
			set[string(c.ContextID)] = true
			// Also offer display names as aliases
			if c.DisplayName != "" {
				set[c.DisplayName] = true
			}
		}
	}
	return sortedKeys(set)
}
