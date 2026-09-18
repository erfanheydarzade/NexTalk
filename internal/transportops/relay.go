package transportops

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// RelayListEntry is one message-capable transport.
type RelayListEntry struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
}

// RelayList returns installed transports declaring the message capability.
func RelayList(d *Deps) ([]RelayListEntry, error) {
	m, err := d.Manager()
	if err != nil {
		return nil, err
	}
	inst, err := m.List()
	if err != nil {
		return nil, err
	}
	var out []RelayListEntry
	for _, in := range inst {
		for _, c := range in.Manifest.Capabilities {
			if c == "message" {
				out = append(out, RelayListEntry{ID: in.Manifest.ID, Enabled: in.Enabled, Running: in.Running})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if d.JSON {
		return out, d.JSONOut(map[string]any{"relays": out})
	}
	if len(out) == 0 {
		d.Human("No message relays installed.")
		return out, nil
	}
	d.Human("Message relays:")
	for _, r := range out {
		state := "disabled"
		if r.Enabled {
			state = "enabled"
		}
		run := ""
		if r.Running {
			run = ", running"
		}
		d.Human("  %-14s %-9s%s", r.ID, state, run)
	}
	return out, nil
}

// RelayPing starts (if enabled) and status-checks a transport.
func RelayPing(d *Deps, id string) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := m.EnsureRunning(ctx, id)
	if err != nil {
		return err
	}
	start := time.Now()
	running, detail, err := tr.Status(ctx)
	if err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{
			"id": id, "running": running, "detail": detail,
			"latency_ms": time.Since(start).Milliseconds(),
		})
	}
	if running {
		d.Human("✓ %s alive (%s).", id, detail)
		return nil
	}
	return fmt.Errorf("%s reports stopped (%s)", id, detail)
}

// RelayInfo shows a transport's manifest and runtime state. Secrets are
// never shown here — only capability/config presence.
func RelayInfo(d *Deps, id string) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	list, err := m.List()
	if err != nil {
		return err
	}
	for _, in := range list {
		if in.Manifest.ID != id {
			continue
		}
		atts := m.Attachments(id)
		if d.JSON {
			return d.JSONOut(map[string]any{
				"id": in.Manifest.ID, "name": in.Manifest.Name,
				"version": in.Manifest.Version, "api_version": in.Manifest.APIVersion,
				"enabled": in.Enabled, "running": in.Running,
				"capabilities": in.Manifest.Capabilities,
				"permissions":  in.Manifest.Permissions,
				"mailboxes_attached": len(atts),
			})
		}
		d.Human("%s — %s", in.Manifest.Name, in.Manifest.ID)
		d.Human("  version: %s (api %s)", in.Manifest.Version, in.Manifest.APIVersion)
		d.Human("  enabled: %v  running: %v", in.Enabled, in.Running)
		d.Human("  capabilities: %v", in.Manifest.Capabilities)
		d.Human("  permissions: %v", in.Manifest.Permissions)
		d.Human("  mailboxes attached: %d", len(atts))
		if in.Manifest.Description != "" {
			d.Human("  %s", in.Manifest.Description)
		}
		return nil
	}
	return fmt.Errorf("transport: %q not installed", id)
}
