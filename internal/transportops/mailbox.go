package transportops

import (
	"fmt"
	"strings"

	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
)

// MailboxList lists conversation threads with unread counts.
func MailboxList(d *Deps, identity string) error {
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	st, err := mailbox.Load(identity)
	if err != nil {
		return err
	}
	threads := st.List()
	if d.JSON {
		rows := make([]map[string]any, 0, len(threads))
		for _, t := range threads {
			rows = append(rows, map[string]any{"key": t.Key, "title": t.Title, "messages": len(t.Messages)})
		}
		return d.JSONOut(map[string]any{"threads": rows})
	}
	if len(threads) == 0 {
		d.Human("Mailbox empty. Poll a transport to receive.")
		return nil
	}
	for _, t := range threads {
		title := t.Title
		if title == "" {
			title = shortHex(t.Key)
		}
		unread := 0
		for _, m := range t.Messages {
			if !m.IsRead {
				unread++
			}
		}
		if unread > 0 {
			d.Human("  %-20s %3d message(s)  [%d unread]", title, len(t.Messages), unread)
		} else {
			d.Human("  %-20s %3d message(s)", title, len(t.Messages))
		}
	}
	return nil
}

// MailboxRead prints one thread's messages, newest last.
func MailboxRead(d *Deps, identity, thread string) error {
	if identity == "" && d.Session != nil {
		identity = d.Session.Identity
	}
	if identity == "" {
		return fmt.Errorf("no identity: pass -i/--id or `use identity` first")
	}
	st, err := mailbox.Load(identity)
	if err != nil {
		return err
	}
	var found *mailbox.Thread
	for _, t := range st.List() {
		if t.Key == thread || t.Title == thread ||
			strings.HasPrefix(t.Key, thread) || strings.HasPrefix(t.Title, thread) {
			found = t
			break
		}
	}
	if found == nil {
		return fmt.Errorf("no thread %q (see `mailbox`)", thread)
	}
	if d.JSON {
		return d.JSONOut(map[string]any{"thread": found.Key, "messages": found.Messages})
	}
	d.Human("Thread %s:", found.Title)
	for _, m := range found.Messages {
		who := string(m.Direction)
		if m.Sender != "" {
			who = shortHex(m.Sender)
		}
		d.Human("  [%s] %s", who, m.Body)
	}
	return nil
}
