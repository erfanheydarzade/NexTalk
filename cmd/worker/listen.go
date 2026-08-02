package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
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
			fmt.Printf("[+] Message from %s (%s):\n%s\n", e.Sender, e.Encoding, e.Message)
		case "error":
			fmt.Printf("[✗] %s\n", e.Message)
		default:
			fmt.Printf("[?] Unknown event: %s\n", e.Type)
		}
	}
}

// dispatch routes an incoming raw envelope body and returns a single ListenEvent.
func dispatch(
	cl Client.Client,
	ctx context.Context,
	engine *core.Engine,
	r relay.Relay,
	selfPriv ed25519.PrivateKey,
	body []byte,
) (*ListenEvent, error) {

	t, data, err := workerrelay.UnwrapEnvelope(body)
	if err != nil {
		return nil, fmt.Errorf("unwrap envelope: %w", err)
	}

	switch t {
	case relay.TypeOffer:
		return handleOffer(cl, ctx, engine, r, selfPriv, data)

	case relay.TypeAnswer:
		return handleAnswer(cl, engine, data)

	case relay.TypeMessage:
		return handleMessage(cl, engine, data)

	default:
		return nil, fmt.Errorf("unknown envelope type: %d", t)
	}
}

func handleOffer(
	cl Client.Client,
	ctx context.Context,
	engine *core.Engine,
	r relay.Relay,
	selfPriv ed25519.PrivateKey,
	data []byte,

) (*ListenEvent, error) {

	var offer core.HandShakeOffer
	if err := json.Unmarshal(data, &offer); err != nil {
		return nil, fmt.Errorf("unmarshal offer: %w", err)
	}

	answerBytes, err := cl.AcceptOffer(data)
	if err != nil {
		return nil, fmt.Errorf("accept offer: %w", err)
	}

	if err := sendEnvelope(
		ctx,
		r,
		selfPriv,
		offer.IdPub,
		relay.TypeAnswer,
		answerBytes,
	); err != nil {
		return nil, fmt.Errorf("send answer: %w", err)
	}

	return &ListenEvent{
		Type: "offer",
		Peer: hex.EncodeToString(offer.IdPub),
		Actions: []ListenAction{
			{
				Type: "answer_sent",
				Peer: hex.EncodeToString(offer.IdPub),
			},
		},
	}, nil
}

func handleAnswer(
	cl Client.Client,
	engine *core.Engine,
	data []byte,
) (*ListenEvent, error) {

	peerID, err := cl.FinishHandshake(data)
	if err != nil {
		return nil, fmt.Errorf("finish handshake: %w", err)
	}

	return &ListenEvent{
		Type: "answer",
		Peer: peerID,
		Actions: []ListenAction{
			{
				Type: "session_established",
				Peer: peerID,
			},
		},
	}, nil
}

func handleMessage(
	cl Client.Client,
	engine *core.Engine,
	data []byte,
) (*ListenEvent, error) {

	senderID, plaintext, err := cl.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	event := &ListenEvent{
		Type:   "message",
		Sender: senderID,
	}

	if utf8.Valid(plaintext) {
		event.Encoding = "utf-8"
		event.Message = string(plaintext)
	} else {
		event.Encoding = "base64"
		event.Message = base64.StdEncoding.EncodeToString(plaintext)
	}

	return event, nil
}
