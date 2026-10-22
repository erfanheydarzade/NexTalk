package ntxhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/erfanheydarzade/NexTalk/internal/transport"
)

// ExportVersion is the export document layout version.
const ExportVersion = 1

type exportDoc struct {
	Version    int           `json:"version"`
	Transports []exportEntry `json:"transports"`
}

type exportEntry struct {
	ID          string         `json:"id"`
	Hash        string         `json:"hash"`    // sha256 of the package, as pinned at install
	Package     string         `json:"package"` // base64 .ntx
	Enabled     bool           `json:"enabled"`
	Attachments []exportAttach `json:"attachments,omitempty"`
}

type exportAttach struct {
	Mailbox    string `json:"mailbox"`
	ReadSecret string `json:"read_secret"` // BEARER: the whole document is secret
	Shard      string `json:"shard"`
	Router     string `json:"router,omitempty"`
	Owner      string `json:"owner,omitempty"`
}

// Export serialises packages, enabled flags and attachments. It contains
// read_secret bearers: JS must store it encrypted. It never contains
// identity key material.
func (h *Host) Export() (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	doc := exportDoc{Version: ExportVersion, Transports: []exportEntry{}}
	for id, r := range h.recs {
		e := exportEntry{ID: id, Hash: r.pinned, Package: base64.StdEncoding.EncodeToString(r.pkg.Raw), Enabled: r.enabled}
		for _, a := range r.attach {
			e.Attachments = append(e.Attachments, exportAttach{Mailbox: a.MailboxID, ReadSecret: a.ReadSecret, Shard: a.ShardURL, Router: a.RouterURL, Owner: a.Owner})
		}
		doc.Transports = append(doc.Transports, e)
	}
	sort.Slice(doc.Transports, func(i, j int) bool { return doc.Transports[i].ID < doc.Transports[j].ID })
	b, err := json.Marshal(doc)
	return string(b), err
}

// Import replaces the whole registry with an export. It is all-or-nothing:
// every entry is parsed and its hash re-verified against the recorded pin
// BEFORE anything changes, so one tampered package rejects the import and
// leaves the current state untouched. Restored transports come back
// DISABLED unless flagged enabled (the hash has been re-verified by then).
//
// Limit: the pin travels inside the same document, so this detects
// corruption and partial tampering, not an attacker who rewrites package
// and hash together — protect the export (encrypt it) for that.
func (h *Host) Import(ctx context.Context, js string) error {
	var doc exportDoc
	if err := json.Unmarshal([]byte(js), &doc); err != nil {
		return fmt.Errorf("ntxhost: import: %w", err)
	}
	if doc.Version != ExportVersion {
		return fmt.Errorf("ntxhost: import: unsupported export version %d", doc.Version)
	}
	next := make(map[string]*record, len(doc.Transports))
	for _, e := range doc.Transports {
		raw, err := base64.StdEncoding.DecodeString(e.Package)
		if err != nil {
			return fmt.Errorf("ntxhost: import %q: package: %w", e.ID, err)
		}
		pkg, err := Inspect(raw)
		if err != nil {
			return fmt.Errorf("ntxhost: import %q: %w", e.ID, err)
		}
		if err := pkg.Verify(e.Hash); err != nil {
			return fmt.Errorf("ntxhost: import %q: %w", e.ID, err)
		}
		if pkg.Manifest.ID != e.ID {
			return fmt.Errorf("ntxhost: import: entry id %q does not match package id %q", e.ID, pkg.Manifest.ID)
		}
		if _, dup := next[e.ID]; dup {
			return fmt.Errorf("ntxhost: import: duplicate id %q", e.ID)
		}
		rec := &record{pkg: pkg, pinned: e.Hash, enabled: e.Enabled}
		for _, a := range e.Attachments {
			att := transport.Attachment{MailboxID: a.Mailbox, ReadSecret: a.ReadSecret, ShardURL: a.Shard, RouterURL: a.Router, Owner: a.Owner}
			if _, _, err := decodeAttachment(att); err != nil {
				return fmt.Errorf("ntxhost: import %q: attachment: %w", e.ID, err)
			}
			if att.ShardURL == "" {
				return fmt.Errorf("ntxhost: import %q: attachment without shard", e.ID)
			}
			rec.attach = append(rec.attach, att)
		}
		next[e.ID] = rec
	}
	h.mu.Lock()
	old := h.recs
	h.recs = next
	h.mu.Unlock()
	for _, r := range old {
		stopLive(ctx, r.live)
	}
	return nil
}
