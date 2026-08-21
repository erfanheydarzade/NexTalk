//go:build js && wasm

package wasmbridge

import (
	"context"
	"fmt"
	"syscall/js"

	"github.com/erfanheydarzade/NexTalk/internal/multimsg"
)

// jsContextCreateContext creates a new multi-message context.
// Usage: NexTalk.context.createContext(name)
// Returns: { context_id, display_name, version, creator_id }
func jsContextCreateContext(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.IdentityPrivate == nil {
		return map[string]any{"error": "no identity loaded — call NexTalk.init() first"}
	}

	if len(args) < 1 {
		return map[string]any{"error": "missing context name"}
	}

	name := args[0].String()
	if name == "" {
		return map[string]any{"error": "empty context name"}
	}

	// Initialize fanout if not already done
	if st.Fanout == nil {
		st.ContextStore = multimsg.NewMemoryContextStore()
		st.DeliveryStore = multimsg.NewMemoryDeliveryStore()
		st.Fanout = multimsg.NewFanout(st.ActiveClient, st.relayConn, st.ContextStore, st.DeliveryStore, multimsg.DefaultFanoutConfig())
	}

	ctx, err := st.Fanout.CreateContext(name, st.IdentityPrivate)
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("create context failed: %v", err)}
	}

	return map[string]any{
		"context_id":   string(ctx.ContextID),
		"display_name": ctx.DisplayName,
		"version":      ctx.MetadataVersion,
		"creator_id":   ctx.CreatorID,
	}
}

// jsContextList returns all contexts.
// Usage: NexTalk.context.list()
// Returns: [{ context_id, display_name, version, creator_id }, ...]
func jsContextList(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return []any{}
	}

	ctxs, err := st.Fanout.CtxStore.ListContexts()
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("list contexts failed: %v", err)}
	}

	result := make([]any, 0, len(ctxs))
	for _, c := range ctxs {
		result = append(result, map[string]any{
			"context_id":   string(c.ContextID),
			"display_name": c.DisplayName,
			"version":      c.MetadataVersion,
			"creator_id":   c.CreatorID,
		})
	}
	return result
}

// jsContextAddMember adds a peer to a context.
// Usage: NexTalk.context.addMember(context_id, peer_id)
// Returns: { ok: true }
func jsContextAddMember(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return map[string]any{"error": "no contexts initialized"}
	}

	if len(args) < 2 {
		return map[string]any{"error": "missing context_id or peer_id"}
	}

	ctxID := multimsg.ContextID(args[0].String())
	peerID := args[1].String()

	if err := st.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyEnabled); err != nil {
		return map[string]any{"error": fmt.Sprintf("add member failed: %v", err)}
	}

	return map[string]any{"ok": true}
}

// jsContextExcludeMember excludes a peer from local delivery.
// Usage: NexTalk.context.excludeMember(context_id, peer_id)
// Returns: { ok: true }
func jsContextExcludeMember(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return map[string]any{"error": "no contexts initialized"}
	}

	if len(args) < 2 {
		return map[string]any{"error": "missing context_id or peer_id"}
	}

	ctxID := multimsg.ContextID(args[0].String())
	peerID := args[1].String()

	if err := st.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyExcluded); err != nil {
		return map[string]any{"error": fmt.Sprintf("exclude member failed: %v", err)}
	}

	return map[string]any{"ok": true}
}

// jsContextIncludeMember re-enables an excluded peer.
// Usage: NexTalk.context.includeMember(context_id, peer_id)
// Returns: { ok: true }
func jsContextIncludeMember(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return map[string]any{"error": "no contexts initialized"}
	}

	if len(args) < 2 {
		return map[string]any{"error": "missing context_id or peer_id"}
	}

	ctxID := multimsg.ContextID(args[0].String())
	peerID := args[1].String()

	if err := st.Fanout.SetRecipientPolicy(ctxID, peerID, multimsg.PolicyEnabled); err != nil {
		return map[string]any{"error": fmt.Sprintf("include member failed: %v", err)}
	}

	return map[string]any{"ok": true}
}

// jsContextListMembers returns members of a context with their policies.
// Usage: NexTalk.context.listMembers(context_id)
// Returns: [{ peer_id, policy }, ...]
func jsContextListMembers(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return map[string]any{"error": "no contexts initialized"}
	}

	if len(args) < 1 {
		return map[string]any{"error": "missing context_id"}
	}

	ctxID := multimsg.ContextID(args[0].String())

	policies, err := st.Fanout.ListRecipientPolicies(ctxID)
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("list members failed: %v", err)}
	}

	result := make([]any, 0, len(policies))
	for _, p := range policies {
		result = append(result, map[string]any{
			"peer_id": p.Recipient,
			"policy":  p.Policy.String(),
		})
	}
	return result
}

// jsContextSendMulti sends a multi-recipient message.
// Usage: NexTalk.context.sendMulti(context_id, message)
// Returns: { message_id, deliveries: [{ recipient, status, error }] }
func jsContextSendMulti(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return map[string]any{"error": "no contexts initialized"}
	}

	if len(args) < 2 {
		return map[string]any{"error": "missing context_id or message"}
	}

	ctxID := multimsg.ContextID(args[0].String())
	message := args[1].String()

	// Get effective recipients
	policies, err := st.Fanout.ListRecipientPolicies(ctxID)
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("context not found: %v", err)}
	}

	var recipients []string
	for _, p := range policies {
		if p.Policy != multimsg.PolicyBlocked && p.Policy != multimsg.PolicyExcluded {
			recipients = append(recipients, p.Recipient)
		}
	}

	if len(recipients) == 0 {
		return map[string]any{"error": "no enabled recipients in context"}
	}

	result, err := st.Fanout.SendMultiMessage(context.Background(), ctxID, []byte(message), recipients)
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("send multi failed: %v", err)}
	}

	deliveries := make([]any, 0, len(result.Deliveries))
	for _, d := range result.Deliveries {
		entry := map[string]any{
			"recipient": d.Recipient,
			"status":    d.Status.String(),
		}
		if d.Error != nil {
			entry["error"] = d.Error.Error()
		}
		deliveries = append(deliveries, entry)
	}

	return map[string]any{
		"message_id": string(result.MessageID),
		"deliveries": deliveries,
		"sent":       result.SuccessCount(),
		"pending":    result.PendingCount(),
		"failed":     result.FailedCount(),
	}
}

// jsContextGetEffectiveRecipients returns the effective recipient list for a context.
// Usage: NexTalk.context.getEffectiveRecipients(context_id)
// Returns: [peer_id, ...]
func jsContextGetEffectiveRecipients(this js.Value, args []js.Value) any {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.Fanout == nil {
		return map[string]any{"error": "no contexts initialized"}
	}

	if len(args) < 1 {
		return map[string]any{"error": "missing context_id"}
	}

	ctxID := multimsg.ContextID(args[0].String())

	policies, err := st.Fanout.ListRecipientPolicies(ctxID)
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("context not found: %v", err)}
	}

	result := make([]any, 0, len(policies))
	for _, p := range policies {
		if p.Policy != multimsg.PolicyBlocked && p.Policy != multimsg.PolicyExcluded {
			result = append(result, p.Recipient)
		}
	}
	return result
}
