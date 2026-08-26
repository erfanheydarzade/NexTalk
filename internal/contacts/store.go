// Package contacts implements NexTalk's contacts book.
//
// Contacts are just human-friendly aliases for peer IDs — they carry no
// identity secrets (no keys, no sessions) — so unlike a client profile
// (client.Client, persisted to <id>.json) they have no reason to be scoped
// to, or gated behind, any single local identity. The book is therefore a
// single global store shared by every profile on the machine and usable
// without loading (or even having) an active client.
package contacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/erfanheydarzade/NexTalk/internal/binstore"
	"github.com/erfanheydarzade/nanopack"
)

// storeFile is the on-disk location of the global contacts book (nanopack
// binary via internal/binstore). legacyFile is the pre-nanopack JSON path,
// still READ for migration; new writes always go to storeFile.
const (
	storeFile  = "contacts.np"
	legacyFile = "contacts.json"

	// schemaID is this store's nanopack envelope schema ID. Permanent once
	// shipped — see nanopack's wire-compatibility notes.
	schemaID byte = 40
)

// Contact is a named alias for a peer's UserID.
type Contact struct {
	Name   string `json:"name"`
	UserID string `json:"user_id"`
	Note   string `json:"note,omitempty"`
}

// Store is the in-memory global contacts book, persisted to storeFile.
type Store struct {
	Contacts map[string]Contact `json:"contacts"`
}

// contactBin is the nanopack record shape of one Contact.
//
//nanopack:schema id=40
type contactBin struct {
	Name   string `bin:"1"`
	UserID string `bin:"2"`
	Note   string `bin:"3"`
}

func (c *contactBin) MarshalBinID(e *nanopack.Encoder) error {
	e.AddID(1, []byte(c.Name))
	e.AddID(2, []byte(c.UserID))
	e.AddID(3, []byte(c.Note))
	return nil
}

func (c *contactBin) UnmarshalBinID(fields []nanopack.FieldID) error {
	for _, f := range fields {
		switch f.ID {
		case 1:
			c.Name = string(f.Data)
		case 2:
			c.UserID = string(f.Data)
		case 3:
			c.Note = string(f.Data)
		}
	}
	return nil
}

// Load reads the global contacts book from disk. If neither storeFile nor
// the legacy JSON file exists yet (first run), it returns a ready, empty
// Store rather than an error — callers don't need any "identity
// initialised" precondition to use it.
func Load() (*Store, error) {
	if records, err := binstore.Load(storeFile, schemaID); err == nil {
		s := &Store{Contacts: make(map[string]Contact, len(records))}
		for _, rec := range records {
			var cb contactBin
			if nanopack.UnmarshalFastID(rec, &cb) != nil {
				continue // skip corrupted entry rather than fail the load
			}
			s.Contacts[cb.Name] = Contact{Name: cb.Name, UserID: cb.UserID, Note: cb.Note}
		}
		return s, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read contacts store: %w", err)
	}

	// Legacy JSON migration: read old format, then persist in the new one
	// so the migration happens exactly once.
	data, err := os.ReadFile(legacyFile)
	if os.IsNotExist(err) {
		return &Store{Contacts: make(map[string]Contact)}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read contacts store: %w", err)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse contacts store: %w", err)
	}
	if s.Contacts == nil {
		s.Contacts = make(map[string]Contact)
	}
	if err := s.Save(); err != nil {
		// Migration write failure is not fatal — keep the loaded state.
		return &s, nil
	}
	return &s, nil
}

// Save persists the contacts book to storeFile with owner-only permissions.
func (s *Store) Save() error {
	records := make([][]byte, 0, len(s.Contacts))
	for _, c := range s.Contacts {
		rec, err := nanopack.MarshalFastID(&contactBin{Name: c.Name, UserID: c.UserID, Note: c.Note})
		if err != nil {
			return fmt.Errorf("serialize contacts store: %w", err)
		}
		records = append(records, rec)
	}
	if err := binstore.Save(storeFile, schemaID, records); err != nil {
		return fmt.Errorf("write contacts store: %w", err)
	}
	return nil
}

// ── mutations ────────────────────────────────────────────────────────────────

// Add adds a contacts to the book. Returns an error if the name is already
// taken.
func (s *Store) Add(name, userID string) error {
	if s.Contacts == nil {
		s.Contacts = make(map[string]Contact)
	}
	if _, exists := s.Contacts[name]; exists {
		return fmt.Errorf("contacts %q already exists", name)
	}
	s.Contacts[name] = Contact{Name: name, UserID: userID}
	return nil
}

// Remove deletes a contacts by name.
func (s *Store) Remove(name string) error {
	if _, exists := s.Contacts[name]; !exists {
		return fmt.Errorf("contacts %q not found", name)
	}
	delete(s.Contacts, name)
	return nil
}

// Rename changes a contacts's label from oldName to newName.
func (s *Store) Rename(oldName, newName string) error {
	if s.Contacts == nil {
		return fmt.Errorf("contacts %q not found", oldName)
	}
	contact, exists := s.Contacts[oldName]
	if !exists {
		return fmt.Errorf("contacts %q not found", oldName)
	}
	if _, taken := s.Contacts[newName]; taken {
		return fmt.Errorf("contacts %q already exists", newName)
	}
	delete(s.Contacts, oldName)
	contact.Name = newName
	s.Contacts[newName] = contact
	return nil
}

// SetNote attaches (or replaces) a free-text note on a contacts.
func (s *Store) SetNote(name, note string) error {
	if s.Contacts == nil {
		return fmt.Errorf("contacts %q not found", name)
	}
	contact, exists := s.Contacts[name]
	if !exists {
		return fmt.Errorf("contacts %q not found", name)
	}
	contact.Note = note
	s.Contacts[name] = contact
	return nil
}

// ── lookups ──────────────────────────────────────────────────────────────────

// Get looks up a contacts by name and returns it.
func (s *Store) Get(name string) (Contact, error) {
	if s.Contacts == nil {
		return Contact{}, fmt.Errorf("contacts %q not found", name)
	}
	contact, exists := s.Contacts[name]
	if !exists {
		return Contact{}, fmt.Errorf("contacts %q not found", name)
	}
	return contact, nil
}

// Resolve returns the UserID for nameOrID, or nameOrID itself if it isn't a
// known contacts alias. This lets any command (or transport) accept either a
// friendly name or a raw peer ID interchangeably — regardless of which
// client profile (if any) is currently active.
func (s *Store) Resolve(nameOrID string) string {
	if s.Contacts != nil {
		if contact, ok := s.Contacts[nameOrID]; ok {
			return contact.UserID
		}
	}
	return nameOrID
}
