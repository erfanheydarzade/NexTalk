// internal/groupchat/view.go — mailbox rendering shared by every transport's
// shell (and the CLI builders in cli.go), so output never drifts between
// worker / offline / proxy.
package groupchat

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/erfanheydarzade/NexTalk/internal/mailbox"
	"github.com/erfanheydarzade/NexTalk/internal/registry"
	"github.com/erfanheydarzade/NexTalk/internal/ui"
)

// threadTitle returns what to print for a thread: display name / title when
// known, otherwise the truncated peer or context ID.
func threadTitle(t *mailbox.Thread) string {
	if t.Title != "" {
		return t.Title
	}
	return registry.ShortID(t.Key)
}

// RenderMailboxList prints every conversation with unread indicators,
// grouped into direct messages and group threads.
func RenderMailboxList(store *mailbox.Store) {
	if store == nil {
		ui.Errorf("Mailbox unavailable — init or load an identity first.")
		return
	}

	threads := store.List()
	var dms, groups []*mailbox.Thread
	for _, t := range threads {
		if mailbox.IsGroupKey(t.Key) {
			groups = append(groups, t)
		} else {
			dms = append(dms, t)
		}
	}

	if len(threads) == 0 {
		ui.Infof("Mailbox is empty.")
		return
	}

	if len(dms) > 0 {
		fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Direct messages ❖"))
		for _, t := range dms {
			printThreadLine(t)
		}
	}
	if len(groups) > 0 {
		fmt.Printf("\n%s\n", ui.Bold.Sprint("❖ Groups ❖"))
		for _, t := range groups {
			printThreadLine(t)
			printMembersPreview(t)
		}
	}

	fmt.Println("\nType 'mailbox <peer>' or 'mailbox <group>' to read (Tab completes).")
}

func printThreadLine(t *mailbox.Thread) {
	unread := 0
	last := ""
	for _, m := range t.Messages {
		if !m.IsRead {
			unread++
		}
		last = m.Body
	}
	indicator := ""
	if unread > 0 {
		indicator = ui.Warning.Sprintf("  [%d unread]", unread)
	}
	preview := last
	if len(preview) > 40 {
		preview = preview[:37] + "..."
	}
	preview = strings.ReplaceAll(preview, "\n", " ")
	when := formatTime(t.Messages[len(t.Messages)-1].Timestamp)
	fmt.Printf("  %s%s  %s %s\n",
		ui.Info.Sprint(threadTitle(t)), indicator, ui.Comment.Sprint(preview), ui.Comment.Sprint(when))
}

func printMembersPreview(t *mailbox.Thread) {
	seen := make(map[string]bool)
	var members []string
	for _, m := range t.Messages {
		if m.Kind == mailbox.Group && m.Sender != "" && m.Sender != "Me" && !seen[m.Sender] {
			seen[m.Sender] = true
			members = append(members, registry.ShortID(m.Sender))
		}
	}
	if len(members) == 0 {
		return
	}
	const max = 4
	if len(members) > max {
		members = append(members[:max], fmt.Sprintf("+%d more", len(members)-max))
	}
	fmt.Printf("    %s %s\n", ui.Comment.Sprint("with:"), strings.Join(members, ", "))
}

// RenderThread prints a single conversation oldest-first (already marked
// read by the store).
func RenderThread(key string, msgs []mailbox.Message) {
	title := key
	if len(msgs) > 0 && msgs[0].ContextName != "" {
		title = msgs[0].ContextName
	}

	fmt.Printf("\n%s\n", ui.Bold.Sprintf("❖ %s ❖", title))

	if len(msgs) == 0 {
		fmt.Println("  (no messages)")
		return
	}

	day := ""
	for _, m := range msgs {
		d := time.UnixMilli(m.Timestamp).Format("2006-01-02")
		if d != day {
			day = d
			fmt.Printf("\n  %s\n", ui.Comment.Sprint(d))
		}

		author := "Me"
		align := "  "
		style := ui.Success
		if m.Direction == mailbox.Incoming {
			author = shortAuthor(m.Sender)
			align = ""
			style = ui.Info
			if m.Kind == mailbox.Group && m.ContextName != "" {
				author = fmt.Sprintf("%s @ %s", shortAuthor(m.Sender), m.ContextName)
			}
		}

		body := strings.ReplaceAll(strings.TrimRight(m.Body, "\n"), "\n", "\n        ")
		clock := time.UnixMilli(m.Timestamp).Format("15:04")
		fmt.Printf("%s %s  %s %s\n", align, style.Sprint(author), ui.Comment.Sprint(clock), body)
	}
	fmt.Println()
}

func shortAuthor(sender string) string {
	if sender == "" || sender == "Me" {
		return "Me"
	}
	return registry.ShortID(sender)
}

func formatTime(ms int64) string {
	t := time.UnixMilli(ms)
	if time.Since(t) < 24*time.Hour {
		return t.Format("15:04")
	}
	return t.Format("Jan 02")
}

// ResolveThreadKey maps a user-typed argument to a thread key.
//
// Precedence matters: ResolvePeer passes unknown IDs through verbatim (by
// design, so `connect` accepts brand-new peers), which would otherwise
// swallow every group reference before mailbox lookup ever ran. So:
//
//  1. "ctx:..."/"group:..." arguments always mean a group thread.
//  2. A peer whose DM thread already exists wins over same-named groups.
//  3. Ambiguous peer prefixes abort immediately — silently falling through
//     to groups would risk showing the wrong conversation.
//  4. Groups by exact name / context ID / unique ID prefix.
//  5. Otherwise the verbatim peer (no history yet).
func ResolveThreadKey(state *registry.State, arg string) (string, error) {
	store := state.MailboxStore

	if strings.HasPrefix(arg, "ctx:") || strings.HasPrefix(arg, "group:") {
		if store == nil {
			return "", fmt.Errorf("mailbox unavailable — init or load an identity first")
		}
		return store.ResolveThread(arg)
	}

	peer, peerErr := state.ResolvePeer(arg)
	var ambiguous *registry.AmbiguousPeerError
	if errors.As(peerErr, &ambiguous) {
		return "", peerErr // never guess between two peers
	}
	if peerErr == nil && store != nil {
		if _, ok := store.Get(peer); ok {
			return peer, nil
		}
	}
	if peerErr == nil && store == nil {
		return peer, nil
	}

	if store != nil {
		if key, err := store.ResolveThread(arg); err == nil {
			return key, nil
		}
	}

	if peerErr == nil {
		return peer, nil // known/verbatim peer without history yet
	}
	return "", fmt.Errorf("%q matches no peer or group", arg)
}
