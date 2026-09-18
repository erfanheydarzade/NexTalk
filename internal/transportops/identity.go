package transportops

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	Client "github.com/erfanheydarzade/NexTalk/client"
)

// IdentityInit creates a fresh identity, persists it, and selects it.
func IdentityInit(d *Deps) error {
	cl := Client.NewClient()
	if d.Session != nil {
		d.Session.Identity = cl.Id
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"id": cl.Id})
	}
	d.Human("✓ Identity created and selected")
	d.Human("")
	d.Human("ID:")
	d.Human("%s", cl.Id)
	d.Human("")
	d.Human("[i] Next: `use relay <id>` (see `transport list`), then")
	d.Human("    `transport register-identity` — peers cannot reach you until this")
	d.Human("    identity's pubkey is registered with the Router — then `peer connect <peer>`.")
	return nil
}

// IdentityLoad loads an existing identity and selects it.
func IdentityLoad(d *Deps, id string) error {
	cl, err := Client.LoadClient(id)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if d.Session != nil {
		d.Session.Identity = cl.Id
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"id": cl.Id, "sessions": len(cl.Sessions)})
	}
	d.Human("✓ Loaded identity %s (%d session(s)).", shortHex(cl.Id), len(cl.Sessions))
	return nil
}

// IdentityList lists local <id>.json profiles in the working directory.
func IdentityList(d *Deps) error {
	matches, err := filepath.Glob("*.json")
	if err != nil {
		return err
	}
	var ids []string
	for _, m := range matches {
		id := strings.TrimSuffix(filepath.Base(m), ".json")
		if id == "contacts" {
			continue
		}
		if _, err := os.Stat(m); err == nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if d.JSON {
		return d.JSONOut(map[string]any{"identities": ids})
	}
	if len(ids) == 0 {
		d.Human("No local identities. Run `identity init`.")
		return nil
	}
	d.Human("Local identities:")
	for _, id := range ids {
		mark := " "
		if d.Session != nil && d.Session.Identity == id {
			mark = "*"
		}
		d.Human(" %s %s", mark, id)
	}
	return nil
}

// IdentityUse selects the active identity without reloading anything else.
func IdentityUse(d *Deps, id string) error {
	if _, err := Client.LoadClient(id); err != nil {
		return fmt.Errorf("load identity: %w (try `identity list` to see local IDs)", err)
	}
	if d.Session != nil {
		d.Session.Identity = id
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"identity": id})
	}
	d.Human("✓ Using identity %s.", shortHex(id))
	return nil
}

// IdentityInfo shows the active identity. Private key material is never
// printed; only the peer ID and session count.
func IdentityInfo(d *Deps) error {
	id := ""
	if d.Session != nil {
		id = d.Session.Identity
	}
	if id == "" {
		return fmt.Errorf("no identity selected (`use identity` or `identity load`)")
	}
	cl, err := Client.LoadClient(id)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"id": cl.Id, "sessions": len(cl.Sessions)})
	}
	d.Human("Identity: %s", cl.Id)
	d.Human("Sessions: %d", len(cl.Sessions))
	return nil
}
