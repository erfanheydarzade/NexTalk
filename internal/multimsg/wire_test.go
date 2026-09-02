package multimsg

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/erfanheydarzade/NexTalk/client"
)

// TestParseWrappedV2RoundTrip drives a real fan-out send through the v2 wire
// format and verifies the recipient can recover every binding field, the
// signed context descriptor, and the plaintext — with nothing else known
// about the payload in advance.
func TestParseWrappedV2RoundTrip(t *testing.T) {
	alice, bob := setupTestClients(t)
	fanout := setupFanout(alice)

	msgCtx, err := fanout.CreateContext("Release Party", alice.IdentityPrivate)
	if err != nil {
		t.Fatalf("create context: %v", err)
	}
	if err := fanout.SetRecipientPolicy(msgCtx.ContextID, bob.Id, PolicyEnabled); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	result, err := fanout.SendMultiMessage(context.Background(), msgCtx.ContextID, []byte("secret plans"), []string{bob.Id})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	ciphertext := result.Deliveries[0].Ciphertext

	// Recipient side: decrypt through the 1:1 session and parse.
	senderID, wrapped, err := bob.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	parsed, err := ParseWrapped(wrapped)
	if err != nil {
		t.Fatalf("parse wrapped: %v", err)
	}

	if senderID != alice.Id {
		t.Errorf("frame sender = %q, want alice", senderID)
	}
	if parsed.Meta.MessageID != result.MessageID {
		t.Errorf("MessageID = %q, want %q", parsed.Meta.MessageID, result.MessageID)
	}
	if parsed.Meta.ContextID != msgCtx.ContextID {
		t.Errorf("ContextID = %q, want %q", parsed.Meta.ContextID, msgCtx.ContextID)
	}
	if parsed.Meta.Sender != alice.Id {
		t.Errorf("meta sender = %q, want alice", parsed.Meta.Sender)
	}
	if parsed.Meta.Recipient != bob.Id {
		t.Errorf("meta recipient = %q, want bob", parsed.Meta.Recipient)
	}
	if parsed.Meta.Version != msgCtx.MetadataVersion {
		t.Errorf("version = %d, want %d", parsed.Meta.Version, msgCtx.MetadataVersion)
	}
	if !bytes.Equal(parsed.Plaintext, []byte("secret plans")) {
		t.Errorf("plaintext = %q", parsed.Plaintext)
	}
	if parsed.Context == nil {
		t.Fatal("context descriptor missing from v2 payload")
	}
	if parsed.Context.DisplayName != "Release Party" {
		t.Errorf("display name = %q", parsed.Context.DisplayName)
	}
}

// TestParseWrappedLegacyFormat ensures recipients still understand v1
// payloads produced by older senders (AAD || plaintext, no context blob).
func TestParseWrappedLegacyFormat(t *testing.T) {
	aad := buildDeliveryAAD("msg-1", "ctx-1", "aliceID", "bobID", 7)
	wrapped := wrapPlaintext([]byte("old-school"), aad)

	parsed, err := ParseWrapped(wrapped)
	if err != nil {
		t.Fatalf("parse legacy: %v", err)
	}
	if parsed.Meta.MessageID != "msg-1" ||
		parsed.Meta.ContextID != "ctx-1" ||
		parsed.Meta.Sender != "aliceID" ||
		parsed.Meta.Recipient != "bobID" ||
		parsed.Meta.Version != 7 {
		t.Errorf("legacy meta wrong: %+v", parsed.Meta)
	}
	if !bytes.Equal(parsed.Plaintext, []byte("old-school")) {
		t.Errorf("legacy plaintext = %q", parsed.Plaintext)
	}
	if parsed.Context != nil {
		t.Error("legacy payload must not carry context metadata")
	}
}

func TestParseWrappedRejectsTruncated(t *testing.T) {
	aad := buildDeliveryAAD("m", "c", "s", "r", 1)
	if _, err := ParseWrapped(aad[:len(aad)-3]); err == nil {
		t.Fatal("expected error for truncated payload")
	}
	if _, err := ParseWrapped(nil); err == nil {
		t.Fatal("expected error for empty payload")
	}
}

// TestProcessDeliveryEndToEnd is the full group-chat receive path: send via
// one fanout, receive through another (the recipient's), and confirm the
// message lands verified, deduped, and annotated with the right group.
func TestProcessDeliveryEndToEnd(t *testing.T) {
	alice, bob := setupTestClients(t)
	aliceFan := setupFanout(alice)
	bobFan := NewFanout(bob, nil, NewMemoryContextStore(), NewMemoryDeliveryStore(), DefaultFanoutConfig())

	ctxMeta, err := aliceFan.CreateContext("Design Crew", alice.IdentityPrivate)
	if err != nil {
		t.Fatalf("create context: %v", err)
	}
	if err := aliceFan.SetRecipientPolicy(ctxMeta.ContextID, bob.Id, PolicyEnabled); err != nil {
		t.Fatal(err)
	}

	result, err := aliceFan.SendMultiMessage(context.Background(), ctxMeta.ContextID, []byte("standup at 10"), []string{bob.Id})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	inbound, err := bobFan.ProcessDelivery(bob.Id, result.Deliveries[0].Ciphertext)
	if err != nil {
		t.Fatalf("process delivery: %v", err)
	}
	if inbound.Sender != alice.Id {
		t.Errorf("sender = %q, want alice", inbound.Sender)
	}
	if inbound.ContextID() != ctxMeta.ContextID {
		t.Errorf("context id = %q, want %q", inbound.ContextID(), ctxMeta.ContextID)
	}
	if string(inbound.Plaintext) != "standup at 10" {
		t.Errorf("plaintext = %q", inbound.Plaintext)
	}
	if got := inbound.DisplayName(); got != "Design Crew" {
		t.Errorf("display name = %q, want Design Crew", got)
	}
	// The signed descriptor must have been adopted into bob's store so the
	// group survives restarts even if he never created it locally.
	stored, err := bobFan.CtxStore.LoadContext(ctxMeta.ContextID)
	if err != nil {
		t.Fatalf("remote context not applied to recipient store: %v", err)
	}
	if stored.DisplayName != "Design Crew" {
		t.Errorf("stored display name = %q", stored.DisplayName)
	}

	// Redelivery of the same logical message under a *fresh* encryption
	// (e.g. sender retry after reconnect) is deduped rather than shown
	// twice. Identical frames are already rejected by the Double Ratchet.
	aad := buildDeliveryAAD(result.MessageID, ctxMeta.ContextID, alice.Id, bob.Id, ctxMeta.MetadataVersion)
	retry, err := wrapPayloadV2(aad, nil, []byte("standup at 10"))
	if err != nil {
		t.Fatal(err)
	}
	cipher2, err := alice.Sessions[bob.Id].Encrypt(alice.Id, retry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bobFan.ProcessDelivery(bob.Id, cipher2); err != ErrDuplicateDelivery {
		t.Errorf("redelivered logical message err = %v, want ErrDuplicateDelivery", err)
	}
}

// TestProcessDeliveryRejectsTransplant verifies the AAD binding check: a
// ciphertext re-encrypted with a foreign recipient claim must be refused,
// not silently accepted into the wrong conversation.
func TestProcessDeliveryRejectsTransplant(t *testing.T) {
	alice, bob := setupTestClients(t)

	session := alice.Sessions[bob.Id]

	// Craft a v2 payload whose AAD claims carole as the recipient, then
	// seal it on the genuine alice→bob channel.
	aad := buildDeliveryAAD("msg-x", "ctx-x", alice.Id, "caroleID", 1)
	wrapped, err := wrapPayloadV2(aad, nil, []byte("for your eyes only"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := session.Encrypt(alice.Id, wrapped)
	if err != nil {
		t.Fatal(err)
	}

	bobFan := setupFanout(bob)
	if _, err := bobFan.ProcessDelivery(bob.Id, ciphertext); err == nil {
		t.Fatal("transplanted delivery accepted")
	}
}

// TestFanoutPersistsRatchetAcrossProcesses is the regression test for the
// replay rejections seen in real group testing: SendMultiMessage encrypts via
// session.Encrypt directly (not Client.Encrypt), so without an explicit
// SaveClient the advanced send-chain nonces lived only in memory. The next
// process loaded stale state and re-sent with consumed nonces, which every
// receiver hard-rejected ("replay attack or message too old").
func TestFanoutPersistsRatchetAcrossProcesses(t *testing.T) {
	chdirTemp(t)

	alice, bob := setupTestClients(t)

	send := func() []byte { // one "process": load fanout, send, exit
		t.Helper()
		ctxStore, err := NewJSONContextStore(alice.Id+".contexts.json", alice.Id+".policies.json")
		if err != nil {
			t.Fatal(err)
		}
		deliveries, err := NewJSONDeliveryStore(alice.Id + ".deliveries.json")
		if err != nil {
			t.Fatal(err)
		}
		sender := NewFanout(alice, nil, ctxStore, deliveries, DefaultFanoutConfig())

		meta, err := ctxStore.LoadContext(groupIDForTest(t, alice.Id))
		if err != nil {
			t.Fatalf("context missing: %v", err)
		}
		res, err := sender.SendMultiMessage(context.Background(), meta.ContextID, []byte("round"), []string{bob.Id})
		if err != nil {
			t.Fatal(err)
		}
		return res.Deliveries[0].Ciphertext
	}

	// First "process" creates the group and sends round 1.
	ctxStore, err := NewJSONContextStore(alice.Id+".contexts.json", alice.Id+".policies.json")
	if err != nil {
		t.Fatal(err)
	}
	fan := NewFanout(alice, nil, ctxStore, NewMemoryDeliveryStore(), DefaultFanoutConfig())
	meta, err := fan.CreateContext("Persist Crew", alice.IdentityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := fan.SetRecipientPolicy(meta.ContextID, bob.Id, PolicyEnabled); err != nil {
		t.Fatal(err)
	}
	writeGroupIDForTest(t, alice.Id, string(meta.ContextID))
	cipher1 := send()

	bobFan := setupFanout(bob)
	if _, err := bobFan.ProcessDelivery(bob.Id, cipher1); err != nil {
		t.Fatalf("first delivery rejected: %v", err)
	}

	// Second "process" must pick up the ADVANCED ratchet state from disk,
	// not re-send nonce 0.
	alice2, err := client.LoadClient(alice.Id)
	if err != nil {
		t.Fatal(err)
	}
	alice.Sessions = alice2.Sessions // simulate fresh process state
	cipher2 := send()

	inbound, err := bobFan.ProcessDelivery(bob.Id, cipher2)
	if err != nil {
		t.Fatalf("second delivery rejected (ratchet state was not persisted): %v", err)
	}
	if string(inbound.Plaintext) != "round" {
		t.Errorf("plaintext = %q", inbound.Plaintext)
	}
}

// groupIDForTest/writeGroupIDForTest stash the context ID between simulated
// processes, mirroring what the persisted contexts file provides for free.
func groupIDForTest(t *testing.T, ownerID string) ContextID {
	t.Helper()
	data, err := os.ReadFile(ownerID + ".testctx")
	if err != nil {
		t.Fatal(err)
	}
	return ContextID(data)
}

func writeGroupIDForTest(t *testing.T, ownerID, id string) {
	t.Helper()
	if err := os.WriteFile(ownerID+".testctx", []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
}

// chdirTemp keeps the <id>.json / contexts files this test writes out of the
// repo working directory.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

// TestVerifyContextSignatureRejectsForgedCreator pins the real verification:
// metadata signed by key material that does not match the claimed CreatorID
// peer ID must fail, closing the spoofing hole in the old stub.
func TestVerifyContextSignatureRejectsForgedCreator(t *testing.T) {
	realSigner, _ := setupTestClients(t)

	forger := client.NewClient()

	ctx := &MessageContext{
		ContextID:       GenerateContextID(),
		DisplayName:     "Stolen Name",
		MetadataVersion: 1,
		CreatorID:       realSigner.Id, // claims to be someone else
	}
	if err := SignContext(ctx, forger.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContextSignature(ctx); err == nil {
		t.Fatal("forged context signature accepted")
	}

	// The honest creator's signature verifies.
	if err := SignContext(ctx, realSigner.IdentityPrivate); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContextSignature(ctx); err != nil {
		t.Fatalf("legitimate signature rejected: %v", err)
	}
}
