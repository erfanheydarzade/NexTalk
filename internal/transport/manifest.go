package transport

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Known capability and permission vocabularies. Installs declaring anything
// outside these sets are refused (fail closed).
var (
	KnownCapabilities = map[string]bool{
		"message":         true,
		"binary-transfer": true,
		"presence":        true,
		"local-network":   true,
		"p2p":             true,
	}
	KnownPermissions = map[string]bool{
		"network": true,
		"storage": true,
	}
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Manifest is the parsed form of a transport's manifest.json.
// It is distribution metadata (JSON is deliberate here: humans and package
// tooling read it, never the hot-path protocol — that is NanoPack RPC).
type Manifest struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	APIVersion   string   `json:"api_version"`
	Entry        string   `json:"entry"`
	Capabilities []string `json:"capabilities"`
	Permissions  []string `json:"permissions"`
	Description  string   `json:"description,omitempty"`
}

// ParseManifest validates raw manifest.json bytes.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("transport: manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate enforces the manifest contract.
func (m *Manifest) Validate() error {
	if !idRe.MatchString(m.ID) {
		return fmt.Errorf("transport: manifest: bad id %q", m.ID)
	}
	if m.Name == "" {
		return fmt.Errorf("transport: manifest: empty name")
	}
	if m.Version == "" {
		return fmt.Errorf("transport: manifest: empty version")
	}
	if m.APIVersion != "1" {
		return fmt.Errorf("transport: manifest: unsupported api_version %q (core speaks %q)", m.APIVersion, "1")
	}
	if m.Entry == "" || m.Entry != safeEntry(m.Entry) {
		return fmt.Errorf("transport: manifest: bad entry %q", m.Entry)
	}
	if len(m.Capabilities) == 0 {
		return fmt.Errorf("transport: manifest: no capabilities")
	}
	for _, c := range m.Capabilities {
		if !KnownCapabilities[c] {
			return fmt.Errorf("transport: manifest: unknown capability %q", c)
		}
	}
	for _, p := range m.Permissions {
		if !KnownPermissions[p] {
			return fmt.Errorf("transport: manifest: unknown permission %q", p)
		}
	}
	return nil
}

// HasCapability reports whether the manifest declares cap.
func (m *Manifest) HasCapability(cap string) bool {
	for _, c := range m.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// safeEntry rejects path traversal and separators: the entry must be a bare
// file name inside the transport directory.
func safeEntry(e string) string {
	for _, r := range e {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return ""
		}
	}
	if e == "." || e == ".." {
		return ""
	}
	return e
}
