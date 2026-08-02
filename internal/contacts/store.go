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
	"fmt"
	"os"
)

// storeFile is the on-disk location of the global contacts book. It lives
// alongside client profile files but, unlike "<id>.json", isn't named after
// (or tied to) any particular peer identity.
const storeFile = "contacts.json"

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

// Load reads the global contacts book from disk. If storeFile doesn't exist
// yet (first run), it returns a ready, empty Store rather than an error —
// callers don't need any "identity initialised" precondition to use it.
func Load() (*Store, error) {
	data, err := os.ReadFile(storeFile)
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
	return &s, nil
}

// Save persists the contacts book to storeFile with owner-only permissions.
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize contacts store: %w", err)
	}
	if err := os.WriteFile(storeFile, data, 0600); err != nil {
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
