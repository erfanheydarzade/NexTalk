package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds everything needed to construct a Client.
type Config struct {
	// WorkerURL is the base URL of the deployed Cloudflare Worker.
	WorkerURL string

	// HTTPClient allows injecting a custom *http.Client.
	HTTPClient *http.Client
}

// ─── Wire types ───────────────────────────────────────────────────────────────

type createRequest struct {
	Pubkey    string `json:"pubkey"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type createResponse struct {
	ReadToken string `json:"read_token"`
	ExpiresIn int    `json:"expires_in"`
	Created   bool   `json:"created"`
}

type sendRequest struct {
	Pubkey  string `json:"pubkey"`
	Message string `json:"message"`
}

type sendResponse struct {
	Success bool `json:"success"`
	Queued  int  `json:"queued"`
}

type workerMessage struct {
	ID      string `json:"id"`
	Time    int64  `json:"time"`
	Message string `json:"message"`
}

type readResponse struct {
	Messages  []workerMessage `json:"messages"`
	Count     int             `json:"count"`
	CreatedAt int64           `json:"createdAt"`
	Consumed  bool            `json:"consumed"`
}

type workerError struct {
	Message string `json:"error"`
}

// ─── Message ──────────────────────────────────────────────────────────────────

// Message is a decoded envelope returned by Receive.
type Message struct {
	ID         string
	ReceivedAt time.Time
	Body       []byte
}

// ─── Client ───────────────────────────────────────────────────────────────────

// Client is a stateful handle to the worker interaction.
type Client struct {
	workerURL string
	readToken string // Populated after Create()
	http      *http.Client
}

// New creates a Client without requiring a private key upfront.
func New(cfg Config) (*Client, error) {
	if cfg.WorkerURL == "" {
		return nil, fmt.Errorf("mailbox: WorkerURL is required")
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		workerURL: strings.TrimRight(cfg.WorkerURL, "/"),
		http:      hc,
	}, nil
}

// ReadToken returns the current read_token held by the client.
func (c *Client) ReadToken() string { return c.readToken }

// SetReadToken allows manually setting a token if you have persisted it.
func (c *Client) SetReadToken(token string) { c.readToken = token }

// ─── API methods ──────────────────────────────────────────────────────────────

// Create provisions the mailbox on the worker using the provided private key.
// It stores the returned read_token internally.
func (c *Client) Create(ctx context.Context, pkey ed25519.PrivateKey) (string, error) {
	// ۱. تولید Public Key به صورت Hex
	pubkeyHex := hex.EncodeToString(pkey.Public().(ed25519.PublicKey))

	// ۲. امضا کردن درخواست (Authentication)
	ts, sig := c.sign(pubkeyHex, pkey)

	reqBody := createRequest{
		Pubkey:    pubkeyHex,
		Timestamp: ts,
		Signature: sig,
	}

	// ۳. ارسال درخواست
	raw, status, err := c.do(ctx, http.MethodPost, "/create", reqBody)
	if err != nil {
		// باید هم رشته خالی "" و هم error رو برگردونیم
		return "", fmt.Errorf("mailbox: Create: %w", err)
	}

	// ۴. بررسی وضعیت پاسخ
	if status != http.StatusOK {
		return "", fmt.Errorf("mailbox: Create: %w", workerErr(raw, status))
	}

	// ۵. پارس کردن پاسخ
	var resp createResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("mailbox: Create: decode response: %w", err)
	}

	// ۶. ذخیره توکن و بازگشت موفق
	c.readToken = resp.ReadToken
	return pubkeyHex, nil // اینجا هم رشته و هم nil برای خطا
}

// Send delivers a payload to a recipient's public key. No private key needed.
func (c *Client) Send(ctx context.Context, recipientPubkey ed25519.PublicKey, body []byte) error {
	if len(recipientPubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("mailbox: Send: invalid recipient public key")
	}

	reqBody := sendRequest{
		Pubkey:  hex.EncodeToString(recipientPubkey),
		Message: string(body),
	}

	raw, status, err := c.do(ctx, http.MethodPost, "/send", reqBody)
	//log.Printf("status=%d body=%s\n", status, raw)
	if err != nil {
		return fmt.Errorf("mailbox: Send: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("mailbox: Send: %w", workerErr(raw, status))
	}

	return nil
}

// Receive fetches messages. It requires the private key to sign the request.
func (c *Client) Receive(ctx context.Context, pkey ed25519.PrivateKey, peek bool) ([]Message, error) {
	if c.readToken == "" {
		return nil, fmt.Errorf("mailbox: Receive: no read_token available (call Create first)")
	}

	pubkeyHex := hex.EncodeToString(pkey.Public().(ed25519.PublicKey))
	ts, sig := c.sign(pubkeyHex, pkey)

	params := url.Values{}
	params.Set("pubkey", pubkeyHex)
	params.Set("timestamp", ts)
	params.Set("signature", sig)
	if peek {
		params.Set("peek", "1")
	}

	raw, status, err := c.do(ctx, http.MethodGet, "/read?"+params.Encode(), nil)
	//log.Printf("status=%d body=%s\n", status, raw)
	if err != nil {
		return nil, fmt.Errorf("mailbox: Receive: %w", err)
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("mailbox: Receive: %w", workerErr(raw, status))
	}

	var resp readResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("mailbox: Receive: decode response: %w", err)
	}

	msgs := make([]Message, len(resp.Messages))
	for i, m := range resp.Messages {
		msgs[i] = Message{
			ID:         m.ID,
			ReceivedAt: time.UnixMilli(m.Time).UTC(),
			Body:       []byte(m.Message),
		}
	}
	return msgs, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (c *Client) sign(pubkeyHex string, pkey ed25519.PrivateKey) (timestamp, signature string) {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	msg := []byte(pubkeyHex + ":" + ts)
	sig := ed25519.Sign(pkey, msg)
	return ts, hex.EncodeToString(sig)
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.workerURL+path, r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

func workerErr(raw []byte, status int) error {
	var e workerError
	if err := json.Unmarshal(raw, &e); err == nil && e.Message != "" {
		return fmt.Errorf("worker error (HTTP %d): %s", status, e.Message)
	}
	return fmt.Errorf("worker returned HTTP %d", status)
}
