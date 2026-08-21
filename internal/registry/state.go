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
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// ChatMessage is a single in-memory chat entry.
type ChatMessage struct {
	Body   string
	IsRead bool
}

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

	// Mailbox stores received messages keyed by sender peer ID, newest first.
	Mailbox map[string][]ChatMessage

	// KnownPeers is the set of peer IDs this session has seen, from any
	// direction: a peer we sent an offer to, a peer whose offer we accepted,
	// a peer whose answer completed our handshake, or a peer who messaged us.
	//
	// It exists because Mailbox alone is not enough for Tab completion —
	// Mailbox only gains a key once a *message* is exchanged, so a peer ID
	// typed into `connect` (or received via `listen`) would otherwise have to
	// be retyped in full for every later command. Peers are recorded via
	// State.RememberPeer; see peers.go.
	KnownPeers map[string]bool

	// Contexts stores multi-message contexts (groups) for the active client.
	// This is purely local state — it does not mutate any global context metadata.
	Contexts map[string][]ChatMessage

	// ContextStore provides persistence for multi-message contexts.
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
		Mailbox:       make(map[string][]ChatMessage),
		KnownPeers:    make(map[string]bool),
		Contexts:      make(map[string][]ChatMessage),
		ContextStore:  multimsg.NewMemoryContextStore(),
		DeliveryStore: multimsg.NewMemoryDeliveryStore(),
	}
}

// InitFanout initializes the multi-message fanout for the active client.
// Call this after init or load to enable multi-message commands.
func (s *State) InitFanout() {
	if s.ActiveClient == nil {
		return
	}
	s.ContextStore = multimsg.NewMemoryContextStore()
	s.DeliveryStore = multimsg.NewMemoryDeliveryStore()
	s.Fanout = multimsg.NewFanout(s.ActiveClient, s.Worker, s.ContextStore, s.DeliveryStore, multimsg.DefaultFanoutConfig())
}

// ContextCandidates returns the context IDs that `context` subcommands accept.
// These come from the in-memory ContextStore populated during the session.
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
