package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	base58 "github.com/mr-tron/base58"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/core"
	"github.com/erfanheydarzade/NexTalk/internal/config"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
	"github.com/erfanheydarzade/NexTalk/internal/session"
	"github.com/spf13/cobra"
)

// peerIDByteLen is the expected decoded length of a base58 peer ID:
// Ed25519 public key (32 bytes) + SHA3-256(Dilithium public key) (32 bytes).
const peerIDByteLen = 64

// requestTimeout bounds how long a single relay round-trip may take.
const requestTimeout = 15 * time.Second

// ed25519PubFromID extracts the Ed25519 public key (first 32 bytes) from a
// base58-encoded peer ID: base58(Ed25519[32] + sha3_256(Dilithium)[32]).
func ed25519PubFromID(peerID string) ([]byte, error) {
	raw, err := base58.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("base58 decode: %w", err)
	}
	if len(raw) != peerIDByteLen {
		return nil, fmt.Errorf("invalid peer ID: decoded length %d, want %d", len(raw), peerIDByteLen)
	}
	return raw[:32], nil
}

type workerCmd struct {
	engine *core.Engine
	cfg    config.Config
}

func Register(parent *cobra.Command, engine *core.Engine, cfg config.Config) {
	wc := &workerCmd{engine: engine, cfg: cfg}
	group := &cobra.Command{
		Use:   "worker",
		Short: "Use the encrypted worker relay transport",
	}
	group.AddCommand(
		wc.initCmd(),
		wc.connectCmd(),
		wc.listenCmd(),
	)
	parent.AddCommand(group)
}

func (wc *workerCmd) relay() (relay.Relay, error) {
	return workerrelay.New(wc.cfg.WorkerURL)
}

func (wc *workerCmd) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize identity and register a mailbox with the worker",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), requestTimeout)
			defer cancel()

			r, err := wc.relay()
			if err != nil {
				return err
			}
			cl := wc.engine.Initialize()

			pubHex, err := r.Register(ctx, cl.IdentityPrivate)
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}

			expectedPubHex := hex.EncodeToString(cl.IdentityPublic)
			if expectedPubHex != pubHex {
				return fmt.Errorf(
					"identity mismatch: local=%s worker=%s",
					expectedPubHex,
					pubHex,
				)
			}

			if err := session.Save(cl.Id); err != nil {
				return fmt.Errorf("save session: %w", err)
			}
			fmt.Printf("✓ Initialized.\nPeer ID: %s\n", cl.Id)
			return nil
		},
	}
}

func (wc *workerCmd) connectCmd() *cobra.Command {
	var peerID string
	c := &cobra.Command{
		Use:   "connect",
		Short: "Send a handshake offer to a peer via the worker",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), requestTimeout)
			defer cancel()

			// Validate the peer ID up front, before touching the network,
			// so a typo fails fast with a clear message.
			peerPubKey, err := ed25519PubFromID(peerID)
			if err != nil {
				return fmt.Errorf("invalid peer ID: %w", err)
			}

			r, err := wc.relay()
			if err != nil {
				return err
			}
			cl, err := session.Load(wc.engine)
			if err != nil {
				return fmt.Errorf("load session: %w", err)
			}

			offerBytes, err := wc.engine.CreateOffer(peerID)
			if err != nil {
				return fmt.Errorf("create offer: %w", err)
			}

			if err := sendEnvelope(ctx, r, cl.IdentityPrivate, peerPubKey, relay.TypeOffer, offerBytes); err != nil {
				return fmt.Errorf("send offer: %w", err)
			}
			fmt.Printf("✓ Offer sent to %s\n", peerID)
			return nil
		},
	}
	c.Flags().StringVar(&peerID, "peer", "", "Peer ID (base58)")
	_ = c.MarkFlagRequired("peer")
	return c
}

func (wc *workerCmd) listenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "listen",
		Short: "Poll the worker for incoming offers, answers, and messages",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), requestTimeout)
			defer cancel()

			r, err := wc.relay()
			if err != nil {
				return err
			}
			cl, err := session.Load(wc.engine)
			if err != nil {
				return fmt.Errorf("load session: %w", err)
			}
			msgs, err := r.Receive(ctx, cl.IdentityPrivate)
			if err != nil {
				return fmt.Errorf("receive: %w", err)
			}
			for _, m := range msgs {
				if err := dispatch(ctx, wc.engine, r, cl.IdentityPrivate, m.Body); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "dispatch error: %v\n", err)
				}
			}
			return nil
		},
	}
}

func dispatch(ctx context.Context, engine *core.Engine, r relay.Relay, selfPriv ed25519.PrivateKey, body []byte) error {
	var env relay.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}
	switch env.Type {
	case relay.TypeOffer:
		return handleOffer(ctx, engine, r, selfPriv, env.Data)
	case relay.TypeAnswer:
		return handleAnswer(engine, env.Data)
	case relay.TypeMessage:
		return handleMessage(engine, env.Data)
	default:
		return fmt.Errorf("unknown envelope type: %q", env.Type)
	}
}

func handleOffer(ctx context.Context, engine *core.Engine, r relay.Relay, selfPriv ed25519.PrivateKey, data json.RawMessage) error {
	var offer Client.HandshakeOffer
	if err := json.Unmarshal(data, &offer); err != nil {
		return fmt.Errorf("unmarshal offer: %w", err)
	}

	answerBytes, err := engine.AcceptOffer(data)
	if err != nil {
		return fmt.Errorf("accept offer: %w", err)
	}

	// offer.IdPub is the raw Ed25519 pub bytes the worker expects directly.
	if err := sendEnvelope(ctx, r, selfPriv, offer.IdPub, relay.TypeAnswer, answerBytes); err != nil {
		return fmt.Errorf("send answer: %w", err)
	}
	return nil
}

func handleAnswer(engine *core.Engine, data json.RawMessage) error {
	peerID, err := engine.FinishHandshake(data)
	if err != nil {
		return fmt.Errorf("finish handshake: %w", err)
	}
	fmt.Printf("✓ Secure session established with: %s\n", peerID)
	return nil
}

func handleMessage(engine *core.Engine, data json.RawMessage) error {
	msgB64 := base64.StdEncoding.EncodeToString(data)
	senderID, pt, err := engine.Decrypt(msgB64)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Printf("\n[Received from %s]: %s\n", senderID, pt)
	return nil
}

// sendEnvelope wraps data in a relay.Envelope of the given type and sends it
// to recipientPubKey. Sender-auth signing happens inside r.Send itself (see
// relay.Relay.Send's doc comment) — this just passes the identity key
// through, it does not build SenderAuth here.
func sendEnvelope(ctx context.Context, r relay.Relay, senderPriv ed25519.PrivateKey, recipientPubKey []byte, t relay.Type, data json.RawMessage) error {
	env := relay.Envelope{Type: t, Data: data}
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	return r.Send(ctx, recipientPubKey, payload, senderPriv)
}
