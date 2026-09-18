package shellcmd

import (
	"sort"
	"strings"
)

// Suggest returns up to 3 known command words resembling a mistyped word,
// for "did you mean …?" errors. Candidates are full command paths plus the
// bare leaf names, so both `xfer snd` and `snd` get useful answers.
func Suggest(r *Registry, word string) []string {
	word = strings.ToLower(word)
	type scored struct {
		s string
		d int
	}
	seen := map[string]bool{}
	var cands []string
	paths, cmds := r.AllCommands()
	for i, p := range paths {
		full := strings.Join(p, " ")
		if !seen[full] {
			seen[full] = true
			cands = append(cands, full)
		}
		leaf := p[len(p)-1]
		if !seen[leaf] {
			seen[leaf] = true
			cands = append(cands, leaf)
		}
		for _, a := range cmds[i].Aliases {
			if !seen[a] {
				seen[a] = true
				cands = append(cands, a)
			}
		}
	}
	var ranked []scored
	for _, c := range cands {
		d := levenshtein(word, c)
		// Forgiving threshold that stays quiet on unrelated words.
		if d <= 2 || (len(word) > 4 && d*2 <= len(c)) {
			ranked = append(ranked, scored{c, d})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].d != ranked[j].d {
			return ranked[i].d < ranked[j].d
		}
		return ranked[i].s < ranked[j].s
	})
	var out []string
	for i := 0; i < len(ranked) && i < 3; i++ {
		out = append(out, ranked[i].s)
	}
	return out
}

// levenshtein is the edit distance over runes.
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur := make([]int, len(br)+1)
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}
			del := prev[j] + 1
			ins := cur[j-1] + 1
			sub := prev[j-1] + cost
			cur[j] = del
			if ins < cur[j] {
				cur[j] = ins
			}
			if sub < cur[j] {
				cur[j] = sub
			}
		}
		prev = cur
	}
	return prev[len(br)]
}
