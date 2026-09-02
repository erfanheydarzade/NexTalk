package multimsg

import (
	"testing"

	"github.com/erfanheydarzade/NexTalk/client"
)

func newTestClient(t *testing.T) *client.Client {
	t.Helper()
	return client.NewClient() // writes <id>.json to CWD; tests chdir first
}

// TestListContextsDeterministic pins deterministic ordering: contexts come
// back sorted by ID regardless of insertion or map iteration order.
func TestListContextsDeterministic(t *testing.T) {
	chdirTemp(t)
	store := NewMemoryContextStore()
	cl := newTestClient(t)
	fan := NewFanout(cl, nil, store, NewMemoryDeliveryStore(), DefaultFanoutConfig())

	for _, name := range []string{"Zeta", "alpha", "Mid"} {
		if _, err := fan.CreateContext(name, cl.IdentityPrivate); err != nil {
			t.Fatal(err)
		}
	}

	var first []string
	for _, c := range mustList(t, store) {
		first = append(first, string(c.ContextID))
	}
	for round := 0; round < 5; round++ {
		var next []string
		for _, c := range mustList(t, store) {
			next = append(next, string(c.ContextID))
		}
		for i := range next {
			if next[i] != first[i] {
				t.Fatalf("ordering unstable: %v vs %v", first, next)
			}
		}
	}
	// Sorted ascending by ID.
	for i := 1; i < len(first); i++ {
		if first[i-1] > first[i] {
			t.Fatalf("not sorted: %v", first)
		}
	}
}

// TestListPoliciesDeterministic checks member listings sort by recipient.
func TestListPoliciesDeterministic(t *testing.T) {
	store := NewMemoryContextStore()
	const ctx = "ctx-det"
	for _, p := range []string{"zpeer", "apeer", "mpeer"} {
		store.SavePolicy(&LocalRecipientPolicy{ContextID: ctx, Recipient: p, Policy: PolicyEnabled})
	}
	pols, err := store.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 3 || pols[0].Recipient != "apeer" || pols[2].Recipient != "zpeer" {
		t.Fatalf("policies not sorted: %+v", pols)
	}
}

func mustList(t *testing.T, s ContextStore) []*MessageContext {
	t.Helper()
	ctxs, err := s.ListContexts()
	if err != nil {
		t.Fatal(err)
	}
	return ctxs
}
