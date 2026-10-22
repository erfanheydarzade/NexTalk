package ntxhost

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	workerrelay "github.com/erfanheydarzade/NexTalk/internal/relay/worker"
)

// Capability is a registered mailbox as returned by a Router.
type Capability struct {
	MailboxID  string // 32 lowercase hex (16B)
	ReadSecret string // 64 lowercase hex (32B bearer)
	ShardURL   string
}

// Resolution is a peer's mailbox + shard.
type Resolution struct {
	MailboxID string
	ShardURL  string
}

// Registrar talks to a Router. It is the only place the identity private key
// is handed to anything network-facing, exactly as cmd/worker does: the
// Router is NexTalk's own relay protocol, not a third-party transport.
// Injectable so native tests need no HTTP.
type Registrar interface {
	Register(ctx context.Context, routerURL string, priv ed25519.PrivateKey) (Capability, error)
	Resolve(ctx context.Context, routerURL, peerPubkeyHex string) (Resolution, error)
}

type routerRegistrar struct {
	mu      sync.Mutex
	clients map[string]*workerrelay.RouterClient
}

// RouterRegistrar is the default Registrar (internal/relay/worker's
// RouterClient; net/http becomes fetch() under GOOS=js).
func RouterRegistrar() Registrar {
	return &routerRegistrar{clients: map[string]*workerrelay.RouterClient{}}
}

func (r *routerRegistrar) client(url string) *workerrelay.RouterClient {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[url]
	if !ok {
		c = workerrelay.NewRouterClient(url)
		r.clients[url] = c
	}
	return c
}

func (r *routerRegistrar) Register(ctx context.Context, routerURL string, priv ed25519.PrivateKey) (Capability, error) {
	cap, err := r.client(routerURL).Register(ctx, priv)
	if err != nil {
		return Capability{}, err
	}
	return Capability{MailboxID: cap.MailboxID, ReadSecret: cap.ReadSecret, ShardURL: cap.ShardURL}, nil
}

func (r *routerRegistrar) Resolve(ctx context.Context, routerURL, peerPubkeyHex string) (Resolution, error) {
	res, err := r.client(routerURL).Resolve(ctx, peerPubkeyHex)
	if err != nil {
		return Resolution{}, err
	}
	if res.MailboxID == "" || res.ShardURL == "" {
		return Resolution{}, fmt.Errorf("router returned an incomplete resolution")
	}
	return Resolution{MailboxID: res.MailboxID, ShardURL: res.ShardURL}, nil
}
