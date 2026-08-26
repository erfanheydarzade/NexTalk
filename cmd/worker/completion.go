// cmd/worker/completion.go
//
// Worker-CLI-specific completions. The group-chat ones (contexts, peers,
// threads) live in internal/groupchat so every transport shares them.
package worker

import (
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// storeFileSuffixes are per-identity data files that must never be mistaken
// for loadable <id>.json identities.
var storeFileSuffixes = []string{
	".mailbox", ".contexts", ".policies", ".deliveries",
}

// localIDCandidates lists loadable identity names: every <id>.json in the
// working directory except the per-identity stores and the global contacts.
func localIDCandidates() []string {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		if name == "contacts" {
			continue
		}
		skip := false
		for _, suffix := range storeFileSuffixes {
			if strings.HasSuffix(name, suffix) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// completeLocalID backs cobra flag completion for `-i/--id`: Tab offers the
// local identities available to load.
func completeLocalID(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	out := make([]string, 0, len(localIDCandidates()))
	for _, c := range localIDCandidates() {
		if strings.HasPrefix(c, toComplete) {
			out = append(out, c)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// flagString reads a string flag's current value at completion time.
func flagString(cmd *cobra.Command, name string) string {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}
