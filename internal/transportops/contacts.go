package transportops

import (
	"fmt"
	"sort"

	"github.com/erfanheydarzade/NexTalk/internal/contacts"
)

// ContactAdd maps a friendly name to a peer ID.
func ContactAdd(d *Deps, name, userID string) error {
	s, err := contacts.Load()
	if err != nil {
		return err
	}
	if err := s.Add(name, userID); err != nil {
		return err
	}
	if err := s.Save(); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"added": name, "user_id": userID})
	}
	d.Human("Contact %q added.", name)
	return nil
}

// ContactRemove deletes a contact after confirmation.
func ContactRemove(d *Deps, name string) error {
	ok, err := d.ConfirmOr(fmt.Sprintf("Remove contact %q?", name))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aborted")
	}
	s, err := contacts.Load()
	if err != nil {
		return err
	}
	if err := s.Remove(name); err != nil {
		return err
	}
	if err := s.Save(); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"removed": name})
	}
	d.Human("Contact %q removed.", name)
	return nil
}

// ContactRename renames a contact.
func ContactRename(d *Deps, oldName, newName string) error {
	s, err := contacts.Load()
	if err != nil {
		return err
	}
	if err := s.Rename(oldName, newName); err != nil {
		return err
	}
	if err := s.Save(); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"renamed": oldName, "to": newName})
	}
	d.Human("Contact %q renamed to %q.", oldName, newName)
	return nil
}

// ContactNote attaches a free-text note (empty clears).
func ContactNote(d *Deps, name, note string) error {
	s, err := contacts.Load()
	if err != nil {
		return err
	}
	if err := s.SetNote(name, note); err != nil {
		return err
	}
	if err := s.Save(); err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"noted": name})
	}
	d.Human("Note updated for %q.", name)
	return nil
}

// ContactInfo shows one contact.
func ContactInfo(d *Deps, name string) error {
	s, err := contacts.Load()
	if err != nil {
		return err
	}
	c, err := s.Get(name)
	if err != nil {
		return err
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"name": name, "user_id": c.UserID, "note": c.Note})
	}
	d.Human("%s", name)
	d.Human("  user: %s", c.UserID)
	if c.Note != "" {
		d.Human("  note: %s", c.Note)
	}
	return nil
}

// ContactList lists all contacts sorted by name.
func ContactList(d *Deps) error {
	s, err := contacts.Load()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(s.Contacts))
	for name := range s.Contacts {
		names = append(names, name)
	}
	sort.Strings(names)
	if d.JSON {
		rows := make([]map[string]string, 0, len(names))
		for _, name := range names {
			c := s.Contacts[name]
			rows = append(rows, map[string]string{"name": name, "user_id": c.UserID, "note": c.Note})
		}
		return d.JSONOut(map[string]any{"contacts": rows})
	}
	if len(names) == 0 {
		d.Human("No contacts yet. Use `contact add <name> <userid>`.")
		return nil
	}
	for _, name := range names {
		c := s.Contacts[name]
		if c.Note != "" {
			d.Human("  %-16s %s  (%s)", name, shortHex(c.UserID), c.Note)
		} else {
			d.Human("  %-16s %s", name, shortHex(c.UserID))
		}
	}
	return nil
}
