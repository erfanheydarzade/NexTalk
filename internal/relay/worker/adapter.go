// internal/relay/worker/adapter.go

package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/erfanheydarzade/NexTalk/internal/relay"
)

// ─── REQUIRED relay package additions (v2.2 replication) ────────────────────
//
// This file assumes the following NEW fields exist on types defined in the
// sibling `relay` package (not shown here — add them there):
//
//   relay.RoutingTable:
//     Shards            []relay.ShardIdentity `json:"shards"`             // {URL, PublicKey}
//     ReplicationFactor int                    `json:"replication_factor"`
//
//   relay.ShardIdentity (new type):
//     URL       string `json:"url"`
//     PublicKey string `json:"pubkey"` // hex, may be empty for legacy/manual shards
//
//   relay.MailboxCapability:
//     ReplicaShardURLs []string `json:"replica_shard_urls"`
//
//   relay.PeerResolution:
//     ReplicaShardURLs []string `json:"replica_shard_urls"`
//
// Everything else (Register/Resolve/Send/Receive call shapes) is unchanged;
// these are purely additive fields the Router now includes in its JSON
// responses (see router.js handleRegister / handleResolve). A client built
// against the OLD relay types still works — it'll just never see replicas
// and always talk to a single shard, same as v2.1.

// ─── Router client: routing table + capability + resolve caching ───────────
//
// This is the entire Router-facing surface of the client. Everything below
// is cached aggressively — the Router is contacted at most:
//   - once per RoutingTable TTL / version bump (shared across all peers)
//   - once ever per own identity (Register)
//   - once ever per peer pubkey messaged (Resolve)
// After that, Send/Receive talk to shards directly and never call these.

type RouterClient struct {
	routerURL string
	http      *http.Client

	mu           sync.RWMutex
	table        *relay.RoutingTable
	capabilities map[string]relay.MailboxCapability // keyed by own pubkey hex
	resolutions  map[string]relay.PeerResolution    // keyed by peer pubkey hex
}

func NewRouterClient(routerURL string) *RouterClient {
	return &RouterClient{
		routerURL:    strings.TrimRight(routerURL, "/"),
		http:         http.DefaultClient,
		capabilities: make(map[string]relay.MailboxCapability),
		resolutions:  make(map[string]relay.PeerResolution),
	}
}

// RoutingTable returns the cached signed routing table, refetching only if
// missing or expired. This is the low-frequency call every other cache's
// freshness is judged against.
//
// As of v2.1, the Router no longer wants to be the common source for this:
// it computes and signs the table, then PUSHES it out to every shard, and
// each shard now serves GET /routing_table.json itself from that pushed
// copy. So a refetch here prefers asking a shard we already know about
// (from the table we're refreshing) and only falls back to the Router
// directly — bootstrap (first-ever call, nothing cached yet) or every
// known shard being unreachable/stale.
func (rc *RouterClient) RoutingTable(ctx context.Context) (*relay.RoutingTable, error) {
	rc.mu.RLock()
	cached := rc.table
	rc.mu.RUnlock()
	if cached != nil && !cached.Expired() {
		return cached, nil
	}

	if cached != nil {
		for _, shardURL := range cached.ShardURLs {
			table, err := rc.fetchRoutingTableFrom(ctx, strings.TrimRight(shardURL, "/")+"/routing_table.json")
			if err != nil {
				continue // try the next shard, then fall through to the Router
			}
			rc.mu.Lock()
			rc.table = table
			rc.mu.Unlock()
			return table, nil
		}
	}

	table, err := rc.fetchRoutingTableFrom(ctx, rc.routerURL+"/routing_table.json")
	if err != nil {
		if cached != nil {
			// Every shard and the Router failed us this round — better to
			// hand back a stale-but-signed table than nothing at all;
			// callers can inspect Expired() themselves if they need to know.
			return cached, nil
		}
		return nil, err
	}

	rc.mu.Lock()
	rc.table = table
	rc.mu.Unlock()
	return table, nil
}

func (rc *RouterClient) fetchRoutingTableFrom(ctx context.Context, url string) (*relay.RoutingTable, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create routing_table request: %w", err)
	}
	resp, err := rc.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch routing_table from %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d for routing_table.json", url, resp.StatusCode)
	}

	var table relay.RoutingTable
	if err := json.NewDecoder(resp.Body).Decode(&table); err != nil {
		return nil, fmt.Errorf("decode routing_table from %s: %w", url, err)
	}
	// Callers wanting strict verification should Ed25519-verify `table.Signature`
	// against `table.RouterPublicKey` over the canonical body here; omitted
	// for brevity but REQUIRED in a production client — pin the Router's
	// public key out-of-band rather than trusting whatever a shard or the
	// Router hands back. This matters MORE now that a shard is in the
	// serving path: a shard is untrusted storage, so the client verifying
	// the Router's signature (not just TLS to the shard) is what actually
	// keeps a compromised or malicious shard from feeding a forged table.

	return &table, nil
}

// Register mints (or returns the cached) mailbox capability for this
// identity. Safe to call on every app start — it's a no-op network-wise
// once cached and unexpired.
func (rc *RouterClient) Register(ctx context.Context, priv ed25519.PrivateKey) (relay.MailboxCapability, error) {
	pubkeyHex, timestamp, sig := signPubkeyTimestamp(priv, "register")

	rc.mu.RLock()
	cached, ok := rc.capabilities[pubkeyHex]
	rc.mu.RUnlock()
	if ok && time.Now().UnixMilli() < cached.ExpiresAt {
		return cached, nil
	}

	body, err := json.Marshal(map[string]string{"pubkey": pubkeyHex, "timestamp": timestamp, "signature": sig})
	if err != nil {
		return relay.MailboxCapability{}, fmt.Errorf("marshal register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.routerURL+"/register", bytes.NewReader(body))
	if err != nil {
		return relay.MailboxCapability{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := rc.http.Do(req)
	if err != nil {
		return relay.MailboxCapability{}, fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return relay.MailboxCapability{}, readAPIError(resp)
	}

	var cap relay.MailboxCapability
	if err := decodeJSONResponse(resp, &cap); err != nil {
		return relay.MailboxCapability{}, fmt.Errorf("decode register response: %w", err)
	}

	rc.mu.Lock()
	rc.capabilities[pubkeyHex] = cap
	rc.mu.Unlock()
	return cap, nil
}

// Resolve looks up (or returns the cached) mailbox_id/shard_url for a peer
// pubkey — required before Send can address them directly.
func (rc *RouterClient) Resolve(ctx context.Context, peerPubkeyHex string) (relay.PeerResolution, error) {
	peerPubkeyHex = strings.ToLower(peerPubkeyHex)

	rc.mu.RLock()
	cached, ok := rc.resolutions[peerPubkeyHex]
	rc.mu.RUnlock()
	if ok {
		return cached, nil
	}

	reqURL := fmt.Sprintf("%s/resolve?pubkey=%s", rc.routerURL, url.QueryEscape(peerPubkeyHex))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return relay.PeerResolution{}, err
	}
	resp, err := rc.http.Do(req)
	if err != nil {
		return relay.PeerResolution{}, fmt.Errorf("resolve request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return relay.PeerResolution{}, readAPIError(resp)
	}

	var res relay.PeerResolution
	if err := decodeJSONResponse(resp, &res); err != nil {
		return relay.PeerResolution{}, fmt.Errorf("decode resolve response: %w", err)
	}

	rc.mu.Lock()
	rc.resolutions[peerPubkeyHex] = res
	rc.mu.Unlock()
	return res, nil
}

func signPubkeyTimestamp(priv ed25519.PrivateKey, action string) (pubkeyHex, timestamp, signatureHex string) {
	pub := priv.Public().(ed25519.PublicKey)
	pubkeyHex = hex.EncodeToString(pub)
	timestamp = strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig := ed25519.Sign(priv, []byte(action+":"+pubkeyHex+":"+timestamp))
	signatureHex = hex.EncodeToString(sig)
	return
}

// ─── Adapter: talks directly to shards ──────────────────────────────────────
//
// Adapter satisfies relay.Relay. It no longer resolves its own worker URL
// per instance — every call carries the shard URL that came from the
// RouterClient's cached capability/resolution, since different mailboxes
// (even for the same running process, e.g. multiple contacts) may live on
// different shards.
type Adapter struct {
	router *RouterClient
	http   *http.Client
}

func New(routerURL string) (*Adapter, error) {
	if routerURL == "" {
		return nil, fmt.Errorf("router URL must not be empty")
	}
	return &Adapter{
		router: NewRouterClient(routerURL),
		http:   http.DefaultClient,
	}, nil
}

type apiErrorBody struct {
	Error string `json:"error"`
}

func readAPIError(resp *http.Response) error {
	defer resp.Body.Close()
	const maxSnippet = 200
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxSnippet+1))

	var apiErr apiErrorBody
	if jsonErr := json.Unmarshal(raw, &apiErr); jsonErr == nil && apiErr.Error != "" {
		return fmt.Errorf("request returned status %d: %s", resp.StatusCode, apiErr.Error)
	}
	if len(raw) > 0 {
		snippet := string(raw)
		truncated := ""
		if len(raw) > maxSnippet {
			snippet = string(raw[:maxSnippet])
			truncated = "... (truncated)"
		}
		return fmt.Errorf("request returned status %d: %q%s", resp.StatusCode, snippet, truncated)
	}
	return fmt.Errorf("request returned status %d", resp.StatusCode)
}

func decodeJSONResponse(resp *http.Response, target interface{}) error {
	err := json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return fmt.Errorf(
			"response was not valid JSON (status %d, content-type %q): %w",
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			err,
		)
	}

	return nil
}

// ─── Register (/register via Router, cached) ─────────────────────────────

func (a *Adapter) Register(
	ctx context.Context,
	privateKey []byte,
) (string, error) {

	priv := ed25519.PrivateKey(privateKey)

	_, err := a.router.Register(ctx, priv)
	if err != nil {
		return "", err
	}

	pub := priv.Public().(ed25519.PublicKey)

	return hex.EncodeToString(pub), nil
}

// ─── Send (direct to shard) ──────────────────────────────────────────────

type sendRequestBody struct {
	MailboxID string           `json:"mailbox_id"`
	Message   string           `json:"message"`
	Sender    relay.SenderAuth `json:"sender"`
}

// Send resolves recipientMailboxID's shard via the (cached) Router
// resolution the caller looked up ahead of time and talks to it directly.
// Callers should obtain recipientMailboxID via a prior call to
// a.router.Resolve(ctx, recipientPubkeyHex) — see SendToPubkey below for the
// common-case convenience wrapper.
func (a *Adapter) sendToShard(ctx context.Context, shardURL, recipientMailboxID string, payload []byte, senderPriv ed25519.PrivateKey) error {
	encodedMessage := base64.StdEncoding.EncodeToString(payload)

	senderAuth, err := relay.BuildSenderAuth(senderPriv, recipientMailboxID, []byte(encodedMessage))
	if err != nil {
		return fmt.Errorf("build sender auth: %w", err)
	}

	body := sendRequestBody{MailboxID: strings.ToLower(recipientMailboxID), Message: encodedMessage, Sender: senderAuth}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal send request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(shardURL, "/")+"/send", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("send request to %s: %w", shardURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readAPIError(resp)
	}
	return nil
}

// SendToPubkey is the common-case entry point: resolve the recipient (cached
// after first use) and deliver to their shard, falling back through the
// rest of the replica set if the primary is unreachable. We stop at the
// first shard that accepts the message — that shard is responsible for
// fanning it out to the rest of its own replica set itself (see
// shard/worker.js replicateToSiblings), so we deliberately do NOT fan out
// from the client side too, which would just duplicate the message N times.
func (a *Adapter) SendToPubkey(ctx context.Context, recipientPubKey []byte, payload []byte, senderPriv ed25519.PrivateKey) error {
	res, err := a.router.Resolve(ctx, hex.EncodeToString(recipientPubKey))
	if err != nil {
		return fmt.Errorf("resolve recipient: %w", err)
	}

	candidates := candidateShardURLs(res.ShardURL, res.ReplicaShardURLs)

	var lastErr error
	for _, shardURL := range candidates {
		lastErr = a.sendToShard(ctx, shardURL, res.MailboxID, payload, senderPriv)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("send failed on all %d known replica(s): %w", len(candidates), lastErr)
}

// candidateShardURLs returns primary followed by any other replicas, with
// no duplicates, tolerating a nil/empty replica list (pre-v2.2 Router, or
// REPLICATION_FACTOR=1).
func candidateShardURLs(primary string, replicas []string) []string {
	seen := map[string]bool{primary: true}
	out := []string{primary}
	for _, u := range replicas {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

func (a *Adapter) Send(
	ctx context.Context,
	recipientPubKey []byte,
	payload []byte,
	senderPriv ed25519.PrivateKey,
) error {

	return a.SendToPubkey(
		ctx,
		recipientPubKey,
		payload,
		senderPriv,
	)
}

// SendDirect implements the relay.Relay shape against an already-known
// mailbox id and shard (e.g. from a cached relay.PeerResolution the caller
// manages itself, or a QR-shared capability) — no Router call at all.
// Prefer SendToPubkey unless you're maintaining your own peer cache.
func (a *Adapter) SendDirect(ctx context.Context, shardURL, recipientMailboxID string, payload []byte, senderPriv ed25519.PrivateKey) error {
	return a.sendToShard(ctx, shardURL, recipientMailboxID, payload, senderPriv)
}

// ─── Receive (/read, direct to shard, via cached capability) ─────────────

type readResponseBody struct {
	Messages []struct {
		ID           string `json:"id"`
		Time         int64  `json:"time"`
		Message      string `json:"message"`
		SenderPubkey string `json:"senderPubkey"`
	} `json:"messages"`
	Count     int   `json:"count"`
	CreatedAt int64 `json:"createdAt"`
	Consumed  bool  `json:"consumed"`
}

func (a *Adapter) receiveCapability(ctx context.Context, cap relay.MailboxCapability) ([]relay.Message, error) {
	query := url.Values{
		"mailbox_id":  {cap.MailboxID},
		"read_secret": {cap.ReadSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cap.ShardURL, "/")+"/read?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read request to %s: %w", cap.ShardURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}

	var parsed readResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode read response: %w", err)
	}

	msgs := make([]relay.Message, 0, len(parsed.Messages))
	for _, m := range parsed.Messages {
		decoded, err := base64.StdEncoding.DecodeString(m.Message)
		if err != nil {
			decoded = []byte(m.Message)
		}
		msgs = append(msgs, relay.Message{Body: decoded})
	}
	return msgs, nil
}

func (a *Adapter) Receive(
	ctx context.Context,
	privateKey []byte,
) ([]relay.Message, error) {

	cap, err := a.router.Register(
		ctx,
		ed25519.PrivateKey(privateKey),
	)
	if err != nil {
		return nil, err
	}

	// Read the primary first (the common, fast path); a message replicated
	// there is consumed there and never touches the other replicas at all.
	// Only fall back to siblings if the primary itself is unreachable —
	// e.g. it's down and this is genuinely the only way to recover
	// messages that got replicated elsewhere before the primary died.
	var lastErr error
	for _, shardURL := range candidateShardURLs(cap.ShardURL, cap.ReplicaShardURLs) {
		attemptCap := cap
		attemptCap.ShardURL = shardURL
		msgs, err := a.receiveCapability(ctx, attemptCap)
		if err == nil {
			return msgs, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("receive failed on all known replica(s): %w", lastErr)
}

// UnwrapEnvelope splits a raw binary payload back into its Type and Data.
func UnwrapEnvelope(raw []byte) (relay.Type, []byte, error) {
	if len(raw) < 1 {
		return 0, nil, fmt.Errorf("envelope too short: %d bytes", len(raw))
	}
	return relay.Type(raw[0]), raw[1:], nil
}
