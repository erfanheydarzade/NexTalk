package multimsg

import (
	"context"
	"testing"

	"github.com/erfanheydarzade/NexTalk/client"
)

// TestCLIContextCreateAndList verifies that context creation persists
// and appears in the context list (simulating CLI `context create` + `context list`).
func TestCLIContextCreateAndList(t *testing.T) {
	alice, _ := setupTestClients(t)
	fanout := setupFanout(alice)

	// Create context
	ctx, err := fanout.CreateContext("Test Group", alice.IdentityPrivate)
	if err != nil {
		t.Fatalf("context create: %v", err)
	}

	// Verify it appears in list
	ctxs, err := fanout.CtxStore.ListContexts()
	if err != nil {
		t.Fatalf("list contexts: %v", err)
	}

	found := false
	for _, c := range ctxs {
		if c.ContextID == ctx.ContextID {
			found = true
			if c.DisplayName != "Test Group" {
				t.Errorf("expected display name 'Test Group', got %s", c.DisplayName)
			}
			break
		}
	}
	if !found {
		t.Fatalf("created context not found in list")
	}
}

// TestCLIContextRename verifies that renaming a context increments
// the metadata version and keeps the signature valid.
func TestCLIContextRename(t *testing.T) {
	alice, _ := setupTestClients(t)
	fanout := setupFanout(alice)

	ctx, _ := fanout.CreateContext("Original", alice.IdentityPrivate)
	originalVersion := ctx.MetadataVersion

	// Rename
	updated, err := fanout.UpdateContext(ctx.ContextID, "Renamed", alice.IdentityPrivate)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}

	if updated.MetadataVersion != originalVersion+1 {
		t.Errorf("expected version %d, got %d", originalVersion+1, updated.MetadataVersion)
	}
	if updated.DisplayName != "Renamed" {
		t.Errorf("expected 'Renamed', got %s", updated.DisplayName)
	}

	// Verify signature is still valid
	if err := VerifyContextSignature(updated); err != nil {
		t.Errorf("signature invalid after rename: %v", err)
	}
}

// TestCLILocalExclusion verifies that excluding a recipient
// removes them from the effective delivery set.
func TestCLILocalExclusion(t *testing.T) {
	alice, bob, charlie := setupThreeClients(t)
	fanout := setupFanout(alice)

	ctx, _ := fanout.CreateContext("Test", alice.IdentityPrivate)
	fanout.SetRecipientPolicy(ctx.ContextID, bob.Id, PolicyEnabled)
	fanout.SetRecipientPolicy(ctx.ContextID, charlie.Id, PolicyEnabled)

	// Both should be effective
	effective, _ := fanout.GetEffectiveRecipients(ctx.ContextID, []string{bob.Id, charlie.Id})
	if len(effective) != 2 {
		t.Fatalf("expected 2 effective recipients, got %d", len(effective))
	}

	// Exclude charlie
	if err := fanout.SetRecipientPolicy(ctx.ContextID, charlie.Id, PolicyExcluded); err != nil {
		t.Fatalf("exclude: %v", err)
	}

	effective, _ = fanout.GetEffectiveRecipients(ctx.ContextID, []string{bob.Id, charlie.Id})
	if len(effective) != 1 {
		t.Errorf("expected 1 effective recipient after exclude, got %d", len(effective))
	}
	if effective[0] != bob.Id {
		t.Errorf("expected bob to remain, got %s", effective[0])
	}
}

// TestCLIReEnable verifies that re-enabling an excluded recipient
// restores them to the effective delivery set.
func TestCLIReEnable(t *testing.T) {
	alice, bob, _ := setupThreeClients(t)
	fanout := setupFanout(alice)

	ctx, _ := fanout.CreateContext("Test", alice.IdentityPrivate)
	fanout.SetRecipientPolicy(ctx.ContextID, bob.Id, PolicyExcluded)

	// Bob should be excluded
	effective, _ := fanout.GetEffectiveRecipients(ctx.ContextID, []string{bob.Id})
	if len(effective) != 0 {
		t.Fatalf("expected 0 effective recipients, got %d", len(effective))
	}

	// Re-enable bob
	if err := fanout.SetRecipientPolicy(ctx.ContextID, bob.Id, PolicyEnabled); err != nil {
		t.Fatalf("re-enable: %v", err)
	}

	effective, _ = fanout.GetEffectiveRecipients(ctx.ContextID, []string{bob.Id})
	if len(effective) != 1 {
		t.Errorf("expected 1 effective recipient after re-enable, got %d", len(effective))
	}
}

// TestCLIMultiSend verifies that send-multi creates one logical message
// with independent ciphertexts per recipient.
func TestCLIMultiSend(t *testing.T) {
	alice, bob, charlie := setupThreeClientsWithSessions(t)
	fanout := setupFanout(alice)

	ctx, _ := fanout.CreateContext("Test", alice.IdentityPrivate)
	fanout.SetRecipientPolicy(ctx.ContextID, bob.Id, PolicyEnabled)
	fanout.SetRecipientPolicy(ctx.ContextID, charlie.Id, PolicyEnabled)

	result, err := fanout.SendMultiMessage(context.Background(), ctx.ContextID, []byte("hello group"), []string{bob.Id, charlie.Id})
	if err != nil {
		t.Fatalf("send-multi: %v", err)
	}

	// Verify result structure
	if result.MessageID == "" {
		t.Error("expected non-empty MessageID")
	}
	if len(result.Deliveries) != 2 {
		t.Fatalf("expected 2 deliveries, got %d", len(result.Deliveries))
	}

	// Verify independent ciphertexts
	ciphertexts := make(map[string]bool)
	for _, d := range result.Deliveries {
		if d.Ciphertext == nil {
			t.Errorf("nil ciphertext for %s", d.Recipient)
		}
		key := string(d.Ciphertext)
		if ciphertexts[key] {
			t.Errorf("duplicate ciphertext for %s", d.Recipient)
		}
		ciphertexts[key] = true
	}
}

// TestCLIPartialFailure verifies that partial fan-out failure
// is reported correctly with per-recipient status.
func TestCLIPartialFailure(t *testing.T) {
	alice, bob, _ := setupThreeClients(t)
	fanout := setupFanout(alice)

	ctx, _ := fanout.CreateContext("Test", alice.IdentityPrivate)
	fanout.SetRecipientPolicy(ctx.ContextID, bob.Id, PolicyEnabled)

	result, err := fanout.SendMultiMessage(context.Background(), ctx.ContextID, []byte("hello"), []string{bob.Id, "unknown_peer"})
	if err != nil {
		t.Fatalf("send-multi: %v", err)
	}

	// Should have results for both
	if len(result.Deliveries) == 0 {
		t.Fatal("expected at least one delivery result")
	}

	// Verify counters
	sent := result.SuccessCount()
	pending := result.PendingCount()
	failed := result.FailedCount()

	if sent+pending+failed != len(result.Deliveries) {
		t.Errorf("counter mismatch: %d+%d+%d != %d", sent, pending, failed, len(result.Deliveries))
	}
}

// TestCLIReceiveDedup verifies that receiving the same delivery twice
// results in only one processed message (replay protection).
func TestCLIReceiveDedup(t *testing.T) {
	alice, _, _ := setupThreeClients(t)
	fanout := setupFanout(alice)

	// Simulate receiving a delivery
	deliveryID := GenerateDeliveryID()

	// First time: should succeed
	if !fanout.MarkDeliverySeen(deliveryID) {
		t.Error("first delivery should be accepted")
	}

	// Second time: should be rejected (replay)
	if fanout.MarkDeliverySeen(deliveryID) {
		t.Error("duplicate delivery should be rejected")
	}
}

// TestFanoutResultJSONSerialization verifies that FanoutResult
// can be serialized to JSON for CLI display.
func TestFanoutResultJSONSerialization(t *testing.T) {
	result := &FanoutResult{
		MessageID: MessageID("test-msg"),
		Sender:    "alice",
		Context: &MessageContext{
			ContextID: ContextID("ctx-123"),
		},
		Deliveries: []DeliveryResult{
			{
				DeliveryID: DeliveryID("del-1"),
				Recipient:  "bob",
				Status:     DeliverySent,
				Ciphertext: []byte("encrypted-data"),
			},
			{
				DeliveryID: DeliveryID("del-2"),
				Recipient:  "charlie",
				Status:     DeliveryFailed,
				Error:      context.DeadlineExceeded,
			},
		},
		Timestamp: 1234567890,
	}

	data, err := result.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("empty JSON output")
	}

	// Verify it contains expected fields
	jsonStr := string(data)
	if !containsStr(jsonStr, "test-msg") {
		t.Error("JSON missing message_id")
	}
	if !containsStr(jsonStr, "bob") {
		t.Error("JSON missing recipient")
	}
	if !containsStr(jsonStr, "sent") {
		t.Error("JSON missing status")
	}
}

// Helper: setupThreeClients creates three clients for multi-recipient tests.
func setupThreeClients(t *testing.T) (*client.Client, *client.Client, *client.Client) {
	t.Helper()
	return client.NewClient(), client.NewClient(), client.NewClient()
}

// Helper: setupThreeClientsWithSessions creates three clients with established sessions.
func setupThreeClientsWithSessions(t *testing.T) (*client.Client, *client.Client, *client.Client) {
	t.Helper()
	alice := client.NewClient()
	bob := client.NewClient()
	charlie := client.NewClient()

	// Establish alice-bob session
	offer1, err := alice.CreateOffer(bob.Id)
	if err != nil {
		t.Fatalf("alice create offer bob: %v", err)
	}
	answer1, err := bob.AcceptOffer(offer1)
	if err != nil {
		t.Fatalf("bob accept offer: %v", err)
	}
	if _, err := alice.FinishHandshake(answer1); err != nil {
		t.Fatalf("alice finish handshake bob: %v", err)
	}

	// Establish alice-charlie session
	offer2, err := alice.CreateOffer(charlie.Id)
	if err != nil {
		t.Fatalf("alice create offer charlie: %v", err)
	}
	answer2, err := charlie.AcceptOffer(offer2)
	if err != nil {
		t.Fatalf("charlie accept offer: %v", err)
	}
	if _, err := alice.FinishHandshake(answer2); err != nil {
		t.Fatalf("alice finish handshake charlie: %v", err)
	}

	return alice, bob, charlie
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
