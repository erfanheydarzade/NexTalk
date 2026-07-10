package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	"github.com/spf13/cobra"
)

func (c *Command) ListenCommand() *cobra.Command {
	var localPeer string

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Poll the worker for incoming offers, answers, and messages",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.RunListen(
				cmd.Context(),
				localPeer,
			)
		},
	}

	cmd.Flags().StringVarP(
		&localPeer,
		"id",
		"i",
		"",
		"Local peer ID",
	)

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

func (c *Command) RunListen(ctx context.Context, localPeer string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	r, err := c.relay()
	if err != nil {
		return err
	}

	cl, err := c.engine.LoadClient(localPeer)
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

	output, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

// dispatch routes an incoming raw envelope body and returns a single ListenEvent.
func dispatch(
	ctx context.Context,
	engine *core.Engine,
	r relay.Relay,
	selfPriv ed25519.PrivateKey,
	body []byte,
) (*ListenEvent, error) {

	var env relay.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	switch env.Type {
	case relay.TypeOffer:
		return handleOffer(ctx, engine, r, selfPriv, env.Data)

	case relay.TypeAnswer:
		return handleAnswer(engine, env.Data)

	case relay.TypeMessage:
		return handleMessage(engine, env.Data)

	default:
		return nil, fmt.Errorf("unknown envelope type: %q", env.Type)
	}
}

func handleOffer(
	ctx context.Context,
	engine *core.Engine,
	r relay.Relay,
	selfPriv ed25519.PrivateKey,
	data json.RawMessage,
) (*ListenEvent, error) {

	var offer Client.HandshakeOffer
	if err := json.Unmarshal(data, &offer); err != nil {
		return nil, fmt.Errorf("unmarshal offer: %w", err)
	}

	answerBytes, err := engine.AcceptOffer(data)
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
	engine *core.Engine,
	data json.RawMessage,
) (*ListenEvent, error) {

	peerID, err := engine.FinishHandshake(data)
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
	engine *core.Engine,
	data json.RawMessage,
) (*ListenEvent, error) {

	msgB64 := base64.StdEncoding.EncodeToString(data)

	senderID, plaintext, err := engine.Decrypt(msgB64)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &ListenEvent{
		Type:    "message",
		Sender:  senderID,
		Message: plaintext,
	}, nil
}
