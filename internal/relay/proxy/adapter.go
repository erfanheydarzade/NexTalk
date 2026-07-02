// internal/relay/proxy/adapter.go
package proxy

import (
	"context"
	"encoding/json"

	Client "github.com/erfanheydarzade/NexTalk/client"
	"github.com/erfanheydarzade/NexTalk/crypto"
	"github.com/erfanheydarzade/NexTalk/internal/relay"
	transport "github.com/erfanheydarzade/NexTalk/transport"
)

// Adapter satisfies relay.Relay using the existing proxy HTTP client.
// It translates the Envelope type discriminator into the proxy's
// bucket names ("offers", "answers", "messages").
type Adapter struct {
	inner *transport.ProxyChatStorage
}

func New(proxyURL string) *Adapter {
	return &Adapter{
		inner: transport.NewProxyChatStorage(transport.ProxyConfig{ProxyUrl: proxyURL}),
	}
}

// Register is a no-op for the proxy transport (no mailbox provisioning needed).
func (a *Adapter) Register(_ context.Context, _ []byte) (string, error) {
	return "", nil
}

func (a *Adapter) Send(_ context.Context, recipientPubKey []byte, payload []byte) error {
	recipientID := string(recipientPubKey) // proxy uses string IDs

	var env relay.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return err
	}

	// Route to the correct proxy bucket based on envelope type.
	switch env.Type {
	case relay.TypeOffer:
		var offer Client.HandshakeOffer
		if err := json.Unmarshal(env.Data, &offer); err != nil {
			return err
		}
		return a.inner.WritePayload(recipientID, "offers", offer)

	case relay.TypeAnswer:
		var answer Client.HandshakeAnswer
		if err := json.Unmarshal(env.Data, &answer); err != nil {
			return err
		}
		return a.inner.WritePayload(recipientID, "answers", answer)

	case relay.TypeMessage:
		var msg crypto.SecureMessage
		if err := json.Unmarshal(env.Data, &msg); err != nil {
			return err
		}
		return a.inner.WritePayload(recipientID, "messages", msg)
	}
	return nil
}

func (a *Adapter) Receive(_ context.Context, privateKey []byte) ([]relay.Message, error) {
	myID := string(privateKey) // derive ID as needed for your proxy
	var out []relay.Message

	// Collect offers
	offers, _ := a.inner.ReadPayloads(myID, "offers")
	for _, raw := range offers {
		env := relay.Envelope{Type: relay.TypeOffer, Data: raw}
		b, _ := json.Marshal(env)
		out = append(out, relay.Message{Body: b})
	}
	// Collect answers
	answers, _ := a.inner.ReadPayloads(myID, "answers")
	for _, raw := range answers {
		env := relay.Envelope{Type: relay.TypeAnswer, Data: raw}
		b, _ := json.Marshal(env)
		out = append(out, relay.Message{Body: b})
	}
	// Collect messages
	messages, _ := a.inner.ReadPayloads(myID, "messages")
	for _, raw := range messages {
		env := relay.Envelope{Type: relay.TypeMessage, Data: raw}
		b, _ := json.Marshal(env)
		out = append(out, relay.Message{Body: b})
	}
	return out, nil
}
