package worker

import (
	"context"
	"crypto/ed25519"
	"fmt"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	dispatchPkg "github.com/erfanheydarzade/NexTalk/internal/dispatch"
	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

// ListenCommand builds the `listen` subcommand.
func (c *Command) ListenCommand() *cobra.Command {
	var localPeer string
	var format string

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Poll the worker for incoming offers, answers, and messages",
		// We own all error reporting (human vs json) — cobra must stay silent.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.RunListen(cmd.Context(), localPeer, format)
			return reportAndExit(err, format)
		},
	}

	cmd.Flags().StringVarP(&localPeer, "id", "i", "", "Local peer ID")
	cmd.Flags().StringVar(&format, "format", formatHuman, "Output format: human, json")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

func (c *Command) RunListen(ctx context.Context, localPeer string, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl, err := Client.LoadClient(localPeer)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	deps := newListenDeps(cl, r)

	msgs, err := r.Receive(ctx, cl.IdentityPrivate)
	if err != nil {
		return fmt.Errorf("receive: %w", err)
	}

	response := ListenResponse{
		Events: make([]ListenEvent, 0, len(msgs)),
	}

	for _, msg := range msgs {
		event, err := dispatch(
			*cl,
			ctx,
			c.engine,
			r,
			cl.IdentityPrivate,
			msg.Body,
			deps,
		)
		if err != nil {
			// Collect dispatch errors as events rather than aborting the loop,
			// so every message in the batch is accounted for in the output.
			response.Events = append(response.Events, ListenEvent{
				Type:    "error",
				Message: err.Error(),
			})
			continue
		}

		if event != nil {
			response.Events = append(response.Events, *event)
		}
	}

	if format == formatJSON {
		return writeJSON(response)
	}

	printListenEventsHuman(response.Events)
	return nil
}

// printListenEventsHuman renders events the way an interactive user wants
// them — one blocked per event, no JSON — instead of forcing json+jq on
// anyone who isn't scripting against this command.
func printListenEventsHuman(events []ListenEvent) {
	if len(events) == 0 {
		fmt.Println("[i] No new events.")
		return
	}

	for _, e := range events {
		switch e.Type {
		case "offer":
			fmt.Printf("[+] Offer received from %s (answer sent)\n", e.Peer)
		case "answer":
			fmt.Printf("[+] Session established with %s\n", e.Peer)
		case "message":
			fmt.Printf("[+] Message from %s (%s) — stored in mailbox:\n%s\n", e.Sender, e.Encoding, e.Message)
		case "group_message":
			fmt.Printf("[+] Group message in [%s] from %s — stored in mailbox:\n%s\n",
				e.Context, e.Sender, e.Message)
		case "error":
			fmt.Printf("[✗] %s\n", e.Message)
		default:
			fmt.Printf("[?] Unknown event: %s\n", e.Type)
		}
	}
}

// listenDeps carries the persistent stores a dispatched envelope is recorded
// into. Both fields degrade gracefully to nil (listen still prints events,
// it just cannot persist them).
type listenDeps struct {
	store  *mailbox.Store
	fanout *multimsg.Fanout
}

// newListenDeps opens the identity's persistent mailbox and wires a fanout
// over file-backed context/delivery stores, mirroring what the interactive
// shell does — so CLI-received messages land in exactly the same history.
func newListenDeps(cl *Client.Client, r relay.Relay) *listenDeps {
	d := &listenDeps{}
	if st, err := mailbox.Load(cl.Id); err == nil {
		d.store = st
	}
	ctxStore, deliveryStore, err := multimsg.OpenIdentityStores(cl.Id)
	if err != nil {
		ctxStore = multimsg.NewMemoryContextStore()
		deliveryStore = multimsg.NewMemoryDeliveryStore()
	}
	d.fanout = multimsg.NewFanout(cl, r, ctxStore, deliveryStore, multimsg.DefaultFanoutConfig())
	return d
}

// dispatch routes an incoming raw envelope body through the shared,
// transport-agnostic dispatcher (internal/dispatch) and converts the
// result to this command's ListenEvent shape. Replies (handshake answers)
// go back out over the worker relay.
func dispatch(
	cl Client.Client,
	ctx context.Context,
	engine *core.Engine,
	r relay.Relay,
	selfPriv ed25519.PrivateKey,
	body []byte,
	deps *listenDeps,
) (*ListenEvent, error) {
	_ = engine
	sender := func(ctx context.Context, recipientPub []byte, t relay.Type, payload []byte) error {
		return sendEnvelope(ctx, r, selfPriv, recipientPub, t, payload)
	}
	d := &dispatchPkg.Deps{Client: &cl}
	if deps != nil {
		d.Mailbox = deps.store
		d.Fanout = deps.fanout
	}
	ev, err := dispatchPkg.DispatchFrame(ctx, &cl, selfPriv, body, d, sender)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, nil
	}
	out := &ListenEvent{
		Type:     ev.Type,
		Peer:     ev.Peer,
		Sender:   ev.Sender,
		Encoding: ev.Encoding,
		Message:  ev.Message,
		Context:  ev.Context,
	}
	for _, a := range ev.Actions {
		out.Actions = append(out.Actions, ListenAction{Type: a.Type, Peer: a.Peer})
	}
	return out, nil
}
