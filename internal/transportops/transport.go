package transportops

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Transport management operations: list/install/remove/enable/disable/
// status/config/attach/detach. Pure manager calls plus output policy.

type TransportInfo struct {
	ID           string   `json:"id"`
	Enabled      bool     `json:"enabled"`
	Running      bool     `json:"running"`
	Version      string   `json:"version"`
	APIVersion   string   `json:"api_version"`
	Capabilities []string `json:"capabilities"`
	Permissions  []string `json:"permissions"`
}

// List returns installed transports sorted by id.
func List(d *Deps) ([]TransportInfo, error) {
	m, err := d.Manager()
	if err != nil {
		return nil, err
	}
	inst, err := m.List()
	if err != nil {
		return nil, err
	}
	out := make([]TransportInfo, 0, len(inst))
	for _, in := range inst {
		out = append(out, TransportInfo{
			ID: in.Manifest.ID, Enabled: in.Enabled, Running: in.Running,
			Version: in.Manifest.Version, APIVersion: in.Manifest.APIVersion,
			Capabilities: append([]string{}, in.Manifest.Capabilities...),
			Permissions:  append([]string{}, in.Manifest.Permissions...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if d.JSON {
		return out, d.JSONOut(map[string]any{"transports": out})
	}
	if len(out) == 0 {
		d.Human("No transports installed.")
		return out, nil
	}
	d.Human("Installed transports:")
	d.Human("")
	for _, t := range out {
		state := "disabled"
		if t.Enabled {
			state = "enabled"
		}
		run := ""
		if t.Running {
			run = ", running"
		}
		d.Human("  %-14s %-9s v%-10s caps=%v%s", t.ID, state, t.Version, t.Capabilities, run)
	}
	return out, nil
}

// Install validates, extracts, and hash-pins a .ntx package.
func Install(d *Deps, path string, enable bool) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mf, err := m.Install(ctx, path, enable)
	if err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{
			"id": mf.ID, "version": mf.Version, "enabled": enable,
		})
	}
	st := "disabled (use `transport enable`)"
	if enable {
		st = "enabled"
	}
	d.Human("Installed %q v%s (%s).", mf.ID, mf.Version, st)
	return nil
}

// Remove stops, deletes, and forgets a transport after confirmation.
func Remove(d *Deps, id string) error {
	ok, err := d.ConfirmOr(fmt.Sprintf("Remove transport %q and all its state?", id))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted")
	}
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.Remove(ctx, id); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"removed": id})
	}
	d.Human("Removed %q.", id)
	return nil
}

// Enable marks a transport enabled.
func Enable(d *Deps, id string) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	if err := m.Enable(id); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"enabled": id})
	}
	d.Human("Enabled %q.", id)
	return nil
}

// Disable stops a running transport and marks it disabled.
func Disable(d *Deps, id string) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.Disable(ctx, id); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"disabled": id})
	}
	d.Human("Disabled %q.", id)
	return nil
}

// Status reports one transport, or every running transport without an id.
func Status(d *Deps, id string) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	list, err := m.List()
	if err != nil {
		return err
	}
	toInfo := func(instID string) *TransportInfo {
		for _, in := range list {
			if in.Manifest.ID == instID {
				return &TransportInfo{
					ID: in.Manifest.ID, Enabled: in.Enabled, Running: in.Running,
					Version: in.Manifest.Version, APIVersion: in.Manifest.APIVersion,
					Capabilities: append([]string{}, in.Manifest.Capabilities...),
					Permissions:  append([]string{}, in.Manifest.Permissions...),
				}
			}
		}
		return nil
	}
	if id != "" {
		t := toInfo(id)
		if t == nil {
			return fmt.Errorf("transport: %q not installed", id)
		}
		if d.JSON {
			return d.JSONOut(t)
		}
		d.Human("%s v%s api=%s enabled=%v running=%v caps=%v perms=%v",
			t.ID, t.Version, t.APIVersion, t.Enabled, t.Running, t.Capabilities, t.Permissions)
		return nil
	}
	running := m.Running()
	if d.JSON {
		ids := make([]string, 0, len(running))
		for rid := range running {
			ids = append(ids, rid)
		}
		sort.Strings(ids)
		return d.JSONOut(map[string]any{"running": ids})
	}
	if len(running) == 0 {
		d.Human("No transports running.")
		return nil
	}
	for rid := range running {
		d.Human("%s: running", rid)
	}
	return nil
}

// SetConfig stores an opaque config blob applied at next start.
func SetConfig(d *Deps, id, configJSON string) error {
	m, err := d.Manager()
	if err != nil {
		return err
	}
	if err := m.SetConfig(id, configJSON); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"config_stored": id})
	}
	d.Human("Config stored for %q (applies at next start).", id)
	return nil
}
