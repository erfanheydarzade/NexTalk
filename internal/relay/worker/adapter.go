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

// Adapter satisfies relay.Relay by talking to a mailbox worker shard
// directly over HTTP (no transport.Client dependency — see below for why).
//
// Direct-connect + redirect handling:
//
//	Clients are encouraged to connect straight to their assigned shard,
//	bypassing the router, to avoid the router's shared rate ceiling. If a
//	client is pointed at the wrong shard for a given pubkey (e.g. after a
//	ring resize, or a stale cached URL), the shard responds 409 with
//	{"error":"wrong_shard","correct_worker_url":"..."} (also mirrored in an
//	X-Correct-Worker-Url header). Every method below retries ONCE against
//	that corrected URL and, on success, updates a.workerURL so subsequent
//	calls on this Adapter go straight to the right place. OnRedirect, if
//	set, is also invoked so the caller can persist the corrected URL
//	(e.g. into session storage) beyond this Adapter's lifetime.
//
// This intentionally reimplements what transport.Client used to do
// (Create/Send/Receive) directly against the worker's HTTP API, rather than
// delegating to it, because intercepting a 409 mid-call requires owning the
// request/response cycle — that isn't possible through an opaque
// transport.Client method that just returns (string, error).
type Adapter struct {
	mu         sync.Mutex
	workerURL  string
	http       *http.Client
	OnRedirect func(newWorkerURL string)
}

func New(workerURL string) (*Adapter, error) {
	if workerURL == "" {
		return nil, fmt.Errorf("worker URL must not be empty")
	}
	// Trim any trailing slash(es) — every request below does
	// baseURL+"/create" etc, so a trailing slash on the configured URL would
	// produce a double slash ("https://x.workers.dev//create"), which
	// worker.js's exact url.pathname === "/create" check does NOT match,
	// silently 404ing with no useful error message.
	workerURL = strings.TrimRight(workerURL, "/")
	return &Adapter{
		workerURL: workerURL,
		http:      http.DefaultClient,
	}, nil
}

func (a *Adapter) currentURL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.workerURL
}

func (a *Adapter) setURL(newURL string) {
	newURL = strings.TrimRight(newURL, "/")
	a.mu.Lock()
	a.workerURL = newURL
	a.mu.Unlock()
	if a.OnRedirect != nil {
		a.OnRedirect(newURL)
	}
}

// wrongShardBody is the JSON shape a shard returns when it doesn't own the
// pubkey a request was keyed on (see worker.js checkShardOwnership).
type wrongShardBody struct {
	Error              string `json:"error"`
	CorrectWorkerURL   string `json:"correct_worker_url"`
	ExpectedShardCount int    `json:"expected_shard_count"`
}

// apiErrorBody is the generic error shape every other worker.js failure uses.
type apiErrorBody struct {
	Error string `json:"error"`
}

// doWithRedirect issues one request via buildReq(baseURL), and if the
// response is a 409 wrong_shard, rebuilds and reissues it once against the
// corrected URL, updating a.workerURL on success. buildReq must be safe to
// call twice (no side effects on shared state, fresh io.Reader each time).
func (a *Adapter) doWithRedirect(ctx context.Context, buildReq func(baseURL string) (*http.Request, error)) (*http.Response, error) {
	baseURL := a.currentURL()

	req, err := buildReq(baseURL)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s: %w", baseURL, err)
	}

	if resp.StatusCode == http.StatusConflict {
		var wrongShard wrongShardBody
		if decodeErr := json.NewDecoder(resp.Body).Decode(&wrongShard); decodeErr == nil && wrongShard.Error == "wrong_shard" && wrongShard.CorrectWorkerURL != "" {
			resp.Body.Close()

			correctedReq, err := buildReq(wrongShard.CorrectWorkerURL)
			if err != nil {
				return nil, err
			}
			retryResp, err := a.http.Do(correctedReq)
			if err != nil {
				return nil, fmt.Errorf("retry request to %s: %w", wrongShard.CorrectWorkerURL, err)
			}

			// Only adopt the new URL once the retry actually succeeds against
			// it — don't repoint the adapter based on an unverified claim.
			if retryResp.StatusCode >= 200 && retryResp.StatusCode < 300 {
				a.setURL(wrongShard.CorrectWorkerURL)
			}
			return retryResp, nil
		}
		// 409 but not a recognizable wrong_shard payload — fall through and
		// let the caller handle it as a normal error status.
	}

	return resp, nil
}

func readAPIError(resp *http.Response) error {
	defer resp.Body.Close()

	const maxSnippet = 200
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxSnippet+1))

	var apiErr apiErrorBody
	if jsonErr := json.Unmarshal(raw, &apiErr); jsonErr == nil && apiErr.Error != "" {
		return fmt.Errorf("worker returned status %d: %s", resp.StatusCode, apiErr.Error)
	}

	// Not a recognizable {"error": "..."} body — surface what we actually
	// got instead of a bare status code, so a plain-text 404/HTML error
	// page/wrong-endpoint response is diagnosable from the CLI output
	// directly (see: worker.js's unmatched routes return plain "Not Found",
	// not JSON).
	if len(raw) > 0 {
		snippet := string(raw)
		truncated := ""
		if len(raw) > maxSnippet {
			snippet = string(raw[:maxSnippet])
			truncated = "... (truncated)"
		}
		return fmt.Errorf("worker returned status %d: %q%s", resp.StatusCode, snippet, truncated)
	}
	return fmt.Errorf("worker returned status %d", resp.StatusCode)
}

// signPubkeyTimestamp signs "pubkeyHex:timestamp" as required by worker.js's
// /create and /read auth (see verifyAuth's default signed-message format).
func signPubkeyTimestamp(priv ed25519.PrivateKey) (pubkeyHex, timestamp, signatureHex string) {
	pub := priv.Public().(ed25519.PublicKey)
	pubkeyHex = hex.EncodeToString(pub)
	timestamp = strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig := ed25519.Sign(priv, []byte(pubkeyHex+":"+timestamp))
	signatureHex = hex.EncodeToString(sig)
	return
}

// ─── Register (/create) ─────────────────────────────────────────────────────

type createRequestBody struct {
	PubKey    string `json:"pubkey"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type createResponseBody struct {
	ReadToken string `json:"read_token"`
	ExpiresIn int    `json:"expires_in"`
	Created   bool   `json:"created"`
}

// decodeJSONResponse decodes resp.Body into target, and on failure returns
// an error that includes a snippet of the actual raw body plus status/
// content-type — a bare json.Decode error ("invalid character 'H' looking
// for beginning of value") tells you nothing about what you actually hit
// (wrong URL, a default "Hello World!" Worker template, an HTML error page,
// a proxy intercepting the request, etc). This makes that diagnosable from
// the CLI's error output directly instead of needing to reproduce with curl.
func decodeJSONResponse(resp *http.Response, target interface{}) error {
	const maxSnippet = 200
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSnippet+1))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if jsonErr := json.Unmarshal(raw, target); jsonErr != nil {
		snippet := string(raw)
		truncated := ""
		if len(raw) > maxSnippet {
			snippet = string(raw[:maxSnippet])
			truncated = "... (truncated)"
		}
		contentType := resp.Header.Get("Content-Type")
		return fmt.Errorf(
			"response was not valid JSON (status %d, content-type %q): %q%s — check that the worker URL points at the mailbox worker, not a different service or the default Workers template",
			resp.StatusCode, contentType, snippet, truncated,
		)
	}
	return nil
}

func (a *Adapter) Register(ctx context.Context, privateKey []byte) (string, error) {
	priv := ed25519.PrivateKey(privateKey)
	pubkeyHex, timestamp, sig := signPubkeyTimestamp(priv)

	body := createRequestBody{PubKey: pubkeyHex, Timestamp: timestamp, Signature: sig}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal create request: %w", err)
	}

	resp, err := a.doWithRedirect(ctx, func(baseURL string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/create", bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", readAPIError(resp)
	}

	var created createResponseBody
	if err := decodeJSONResponse(resp, &created); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	return pubkeyHex, nil
}

// ─── Send ────────────────────────────────────────────────────────────────

// sendRequestBody mirrors the JSON shape worker.js's POST /send expects:
//
//	{
//	  "pubkey":  "<recipient hex pubkey>",
//	  "message": "<base64-encoded envelope>",
//	  "sender": {
//	    "pubkey":    "<sender hex pubkey>",
//	    "timestamp": "<unix ms string>",
//	    "signature": "<hex sig>"
//	  }
//	}
type sendRequestBody struct {
	PubKey  string           `json:"pubkey"`
	Message string           `json:"message"`
	Sender  relay.SenderAuth `json:"sender"`
}

// Send transmits payload to recipientPubKey via the mailbox worker's /send
// endpoint, requiring a signed relay.SenderAuth block per the worker's
// sender-authentication update (see worker.js handleSend).
// Send transmits payload to recipientPubKey via the mailbox worker's /send
// endpoint. senderPriv is the caller's identity private key; SenderAuth is
// built HERE, after base64-encoding, over the exact string that ends up in
// the wire request's "message" field — matching worker.js's handleSend,
// which hashes that exact received string. Building auth before encoding
// (as an earlier version of this code did, with the caller pre-building
// SenderAuth) signed different bytes than the server hashed, and every
// signature failed verification.
func (a *Adapter) Send(ctx context.Context, recipientPubKey []byte, payload []byte, senderPriv ed25519.PrivateKey) error {
	encodedMessage := base64.StdEncoding.EncodeToString(payload)

	senderAuth, err := relay.BuildSenderAuth(senderPriv, recipientPubKey, []byte(encodedMessage))
	if err != nil {
		return fmt.Errorf("build sender auth: %w", err)
	}

	body := sendRequestBody{
		PubKey:  hex.EncodeToString(recipientPubKey),
		Message: encodedMessage,
		Sender:  senderAuth,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal send request: %w", err)
	}

	resp, err := a.doWithRedirect(ctx, func(baseURL string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/send", bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return readAPIError(resp)
	}
	return nil
}

// ─── Receive (/read) ─────────────────────────────────────────────────────

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

func (a *Adapter) Receive(ctx context.Context, privateKey []byte) ([]relay.Message, error) {
	priv := ed25519.PrivateKey(privateKey)
	pubkeyHex, timestamp, sig := signPubkeyTimestamp(priv)

	query := url.Values{
		"pubkey":    {pubkeyHex},
		"timestamp": {timestamp},
		"signature": {sig},
	}

	resp, err := a.doWithRedirect(ctx, func(baseURL string) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/read?"+query.Encode(), nil)
	})
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No mailbox / nothing to read yet — not an error condition callers
		// need to treat specially, just an empty inbox.
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
			decoded = []byte(m.Message) // not base64 — treat as raw opaque bytes
		}
		msgs = append(msgs, relay.Message{Body: decoded})
	}
	return msgs, nil
}

// WrapEnvelope is a shared helper used by command handlers.
func WrapEnvelope(t relay.Type, b64data string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return nil, err
	}
	env := relay.Envelope{Type: t, Data: json.RawMessage(raw)}
	return json.Marshal(env)
}
