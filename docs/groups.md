# NexTalk Multi-User Messaging (Fan-Out) Design

## Overview

NexTalk supports multi-user messaging through a **fan-out architecture** — NOT a traditional group chat. This document describes the design decisions, security properties, and implementation details.

## Core Principle

> **NexTalk does not need a cryptographic Group Chat. It needs a logical multi-recipient message layer built on top of independent secure user-to-user channels.**

## Architecture

### The Fan-Out Model

```
                    MultiMessage
                         │
              ┌──────────┼──────────┐
              ↓          ↓          ↓
           Peer A      Peer B     Peer C
              │          │          │
           Session     Session    Session
              │          │          │
           Ratchet     Ratchet    Ratchet
              │          │          │
             AEAD       AEAD       AEAD
```

A multi-user message is a logical message that is **independently encrypted and delivered** to each recipient through their existing 1:1 secure channel with the sender.

### What This Is NOT

This is NOT a traditional group chat with:
- ❌ Shared group ciphertext
- ❌ Group encryption key
- ❌ Group ratchet
- ❌ Group cryptographic state
- ❌ Global membership state

### What This IS

This IS a logical presentation layer that:
- ✅ Reuses existing 1:1 secure channels
- ✅ Creates independent ciphertexts per recipient
- ✅ Provides authenticated context metadata
- ✅ Supports local recipient policies
- ✅ Maintains per-recipient delivery state

## Key Types

### MessageID and DeliveryID

A logical multi-recipient message and each individual recipient delivery are **different objects**:

```
Message M (MessageID: "abc123")
├── Delivery A (DeliveryID: "d1") → Alice
├── Delivery B (DeliveryID: "d2") → Bob
└── Delivery C (DeliveryID: "d3") → Charlie
```

- **MessageID**: Identifies the abstract logical message
- **DeliveryID**: Identifies an individual encrypted delivery to one recipient

This distinction enables:
- Per-recipient delivery acknowledgement
- Retries without regenerating the logical message
- Deduplication at the delivery level
- Partial fan-out failure handling

### MessageContext

```go
type MessageContext struct {
    ContextID       ContextID  // Immutable identifier
    DisplayName     string     // Mutable display name
    MetadataVersion uint64     // Monotonically increasing
    CreatorID       string     // Peer ID of creator
    Signature       []byte     // Ed25519 signature
}
```

The context is **authenticated presentation metadata only**. It contains no cryptographic keys and is not responsible for encryption. The display name is signed by the creator so an untrusted relay cannot silently rename it.

**Key property**: `ContextID` is **immutable** — renaming a context changes `DisplayName` and increments `MetadataVersion`, but never changes `ContextID`.

### MessageDelivery

```go
type MessageDelivery struct {
    DeliveryID DeliveryID  // Unique per-delivery ID
    MessageID  MessageID   // Links to logical message
    Recipient  string      // Peer ID of recipient
    ChannelID  string      // Session/channel identifier
    Ciphertext []byte      // Encrypted via SecurePeer.Encrypt with AAD
    ContextID  ContextID   // Links delivery to its context
    Timestamp  int64       // Unix milliseconds
}
```

Each delivery is a single encrypted delivery to one recipient through their existing 1:1 secure channel. Each delivery is cryptographically independent.

### FanoutResult

```go
type FanoutResult struct {
    MessageID  MessageID
    Sender     string
    Context    *MessageContext
    Deliveries []DeliveryResult
    Timestamp  int64
}

type DeliveryResult struct {
    DeliveryID DeliveryID
    Recipient  string
    Status     DeliveryStatus  // sent, pending, or failed
    Error      error
    Ciphertext []byte
}
```

The `FanoutResult` preserves per-recipient delivery status for **partial fan-out failure** handling. A multi-recipient send is NOT treated as a single indivisible operation.

## Encryption Model

### Per-Recipient Encryption with AAD Binding

When Alice sends "Hello everyone" to Bob, Charlie, and David:

```
Plaintext: "Hello everyone"
|
+--> Alice/Bob channel + AAD(msg_id, ctx_id, alice, bob, v1) --> Ciphertext A
|
+--> Alice/Charlie channel + AAD(msg_id, ctx_id, alice, charlie, v1) --> Ciphertext B
|
+--> Alice/David channel + AAD(msg_id, ctx_id, alice, david, v1) --> Ciphertext C
```

Each ciphertext is produced by the existing `SecurePeer.Encrypt()` method using the sender's session with that specific recipient, with **additional authenticated data (AAD)** binding the delivery to:
- `message_id` — the logical message
- `context_id` — the context
- `sender_id` — who sent it
- `recipient_id` — who should receive it
- `metadata_version` — context version

### AAD Construction

The AAD uses **length-prefixed fields** to avoid ambiguity:

```
AAD = len(msgID)||msgID || len(ctxID)||ctxID || len(sender)||sender || len(recipient)||recipient || version(big-endian uint64)
```

This canonical serialization ensures that:
- `ciphertext(Alice)` cannot be used as `ciphertext(Bob)`
- A delivery from `Context A` cannot be transplanted into `Context B`
- The plaintext is wrapped with AAD before encryption, and verified after decryption

### No Shared Group State

```
WRONG:
plaintext -> group key -> one shared ciphertext

RIGHT:
plaintext -> Alice/Bob channel + AAD -> ciphertext A
plaintext -> Alice/Charlie channel + AAD -> ciphertext B
plaintext -> Alice/David channel + AAD -> ciphertext C
```

## Replay Protection and Deduplication

### Delivery-Level Replay Detection

Each `Fanout` instance maintains an in-memory `seenDeliveries` map:

```go
func (f *Fanout) MarkDeliverySeen(id DeliveryID) bool {
    if f.seenDeliveries[id] {
        return false // Already seen — replay detected
    }
    f.seenDeliveries[id] = true
    return true
}
```

### Properties

- Duplicate deliveries do not cause duplicate message processing
- Retries retain the same `DeliveryID` (no new logical message)
- The underlying crypto session's nonce tracking provides additional replay protection
- Replay state is in-memory; persistent replay protection comes from the crypto layer

## Context Authentication

### Signed Context Descriptors

The context display name is signed by the creator using Ed25519:

```go
func SignContext(ctx *MessageContext, creatorPriv ed25519.PrivateKey) error
func VerifyContext(ctx *MessageContext, creatorPub ed25519.PublicKey) error
```

The signature covers the canonical nanopack serialization of:
- `context_id`
- `display_name`
- `metadata_version`
- `creator_id`

### Version Monotonicity

Context metadata changes (renames, etc.) must have a **monotonically increasing version**:

```
Version 1 → "Friends"
Version 2 → "Gaming"
Version 3 → "NexTalk Dev"
```

An older descriptor **must never** overwrite a newer one:

```go
// ApplyRemoteContext rejects stale versions
if remoteCtx.MetadataVersion <= stored.MetadataVersion {
    return fmt.Errorf("stale context: remote version %d <= stored version %d", ...)
}
```

This prevents **rollback attacks** where an adversary replays an older signed context state.

## Local Policies

### Truly Local State

Recipient selection is **purely local**. Policies such as mute, block, and exclude do not mutate any global context metadata or notify other participants.

```
Alice mutes Bob
```

This does NOT mean "Bob was removed from the context." It means "Alice's local delivery policy excludes Bob from receiving future multi-messages."

### Policy Types

| Policy | Behavior |
|--------|----------|
| `enabled` | Recipient receives deliveries (default) |
| `muted` | Recipient receives deliveries, but UI may suppress notifications |
| `blocked` | No deliveries sent to this recipient |
| `excluded` | Recipient removed from local delivery set |

### Remove vs Block

These are **semantically separate**:

- **Remove** (`PolicyExcluded`): The recipient is no longer part of the local context recipient set. This is a soft removal.
- **Block** (`PolicyBlocked`): The recipient is explicitly prohibited by local policy. This is a hard prohibition.

Both prevent delivery, but they have different semantics and may be displayed differently in the UI.

## Partial Fan-Out Failure

`SendMultiMessage()` does NOT treat a multi-recipient operation as a single indivisible delivery.

### Example

```
Alice   ✓ (sent)
Bob     ✓ (sent)
Charlie ✗ (failed — no session)
```

The result preserves per-recipient status:

```go
result.SuccessCount()  // 2
result.FailedCount()   // 1
result.PendingCount()  // 0
result.AllSent()       // false
```

### Retry Semantics

A failed recipient delivery is independently retryable:
- Retry keeps the same `MessageID`
- Retry keeps the same `DeliveryID`
- Retry does not regenerate the logical message
- Retry does not resend already-successful deliveries

## Persistence

### JSON-Backed Stores

`JSONContextStore` and `JSONDeliveryStore` provide file-based persistence:

```go
store, err := NewJSONContextStore("contexts.json", "policies.json")
```

### Limitations

> **SECURITY NOTE**: This is NOT production-grade crash-safe storage. It uses simple write-to-file semantics without atomic rename, WAL, or fsync. A crash during write may corrupt the file. For production use, replace with SQLite or an append-only log with checksums.

### Crash Safety Properties

- Files are written to a `.tmp` file first, then renamed (atomic on POSIX)
- Corrupted entries are skipped during loading (with validation)
- Version checks prevent stale overwrites
- Duplicate delivery IDs are rejected

## Security Guarantees

| Property | Guarantee |
|----------|-----------|
| No shared group ciphertext | Each recipient gets an independent ciphertext |
| No group key | No group encryption key exists |
| No group ratchet | No group ratchet state |
| No group cryptographic state | No group cryptographic primitives |
| AAD binding | Each ciphertext is bound to its context, message, sender, and recipient |
| Local exclusion | Removing a recipient from fan-out list is purely local |
| Authenticated context | Display name is signed by creator |
| Version monotonicity | Older context versions cannot overwrite newer ones |
| Replay detection | Duplicate deliveries are detected and rejected |
| Per-recipient encryption | Uses existing 1:1 SecurePeer.Encrypt() |
| Forward secrecy | Inherited from existing ratchet |
| Ciphertext integrity | Inherited from existing HMAC-SHA3-256 + XChaCha20-Poly1305 |

## Security Limitations

### Remove ≠ Cryptographic Revocation

> **Removing a recipient does not revoke access to messages that recipient has already received.**

Previously delivered plaintext cannot be cryptographically recalled. Removal affects future recipient selection/delivery according to local policy, but does not provide cryptographic revocation of past messages.

### Local Policy Scope

Local policies (mute, block, exclude) are purely local. They do not:
- Notify other participants
- Modify global context metadata
- Prevent other users from including the same recipient

### JSON Persistence

The JSON-backed stores are intended for local/reference use. They are not production-grade durable storage. Limitations:
- No write-ahead logging
- No fsync guarantees
- No multi-writer concurrency control
- Crash during write may lose recent changes

## Implementation

### Package Structure

```
internal/multimsg/
  types.go      — Core types (MessageContext, MessageDelivery, MultiMessage, FanoutResult)
  fanout.go     — Fanout logic (SendMultiMessage, policies, AAD binding)
  store.go      — ContextStore and DeliveryStore interfaces + implementations
  multimsg_test.go — Security-focused tests
```

### CLI Commands

```
offline/
  offline.go    — REPL with context and multisend commands
```

### Usage

```bash
# Create a context
context create "NexTalk Dev"

# List contexts
context list
contexts

# Show context details
context show <ctx_id>

# Rename a context
context rename <ctx_id> "New Name"

# Add recipients
context add <ctx_id> <peer_id>

# Set policies
context policy <ctx_id> <peer> enabled
context policy <ctx_id> <peer> muted
context policy <ctx_id> <peer> blocked
context policy <ctx_id> <peer> excluded

# Exclude/include recipients (local delivery control)
context exclude <ctx_id> <peer_id>   # Remove from local delivery set
context include <ctx_id> <peer_id>   # Re-enable for local delivery

# List members with policies
context members <ctx_id>

# Send multi-user message
send-multi <ctx_id> "Hello everyone"
```

## CLI and GUI Integration

### Shell Tab Completion

Context IDs and display names are **Tab-completable** in argument slots:

| Command | Completes |
|---------|-----------|
| `send-multi <Tab>` | All context IDs and display names |
| `context show <Tab>` | All context IDs and display names |
| `context add <ctx> <Tab>` | Peer IDs |
| `context exclude <ctx> <Tab>` | Peer IDs |

A context becomes completable the moment it is created via `context create`.

### Worker Mode Integration

Worker mode supports **real multi-message delivery** through the relay:

1. Create a context: `context create "Team"`
2. Add recipients: `context add <ctx> <peer>`
3. Send multi-message: `send-multi <ctx> "Hello team"`

The `listen` command processes incoming multi-message deliveries (type `0x04`).

The `mailbox` command shows both regular 1:1 chats and context conversations.

### Offline Mode Integration

Offline mode supports **local construction and testing** of multi-messages:

1. Create a context: `context create "Test Group"`
2. Add recipients: `context add <ctx> <peer>`
3. Send multi-message: `send-multi <ctx> "Hello"`

Since there is no network delivery, the command shows the generated deliveries and their states.

### FanoutResult JSON Output

The `send-multi` command can serialize results to JSON for scripting:

```go
result.MarshalJSON() // Returns structured delivery status
```

Example output:
```json
{
  "message_id": "abc123...",
  "sender": "alice",
  "context_id": "ctx456...",
  "deliveries": [
    {"delivery_id": "d1", "recipient": "bob", "status": "sent", "ciphertext": "..."},
    {"delivery_id": "d2", "recipient": "charlie", "status": "pending", "error": ""}
  ],
  "timestamp": 1234567890
}
```

## Design Philosophy

> **NexTalk cleanly separates four concerns:**
>
> 1. **Cryptography** (`crypto/`) — primitives only, no protocol decisions
> 2. **Protocol** (`core/`) — handshake and session logic, no transport assumptions
> 3. **Transport** (`transport/`) — untrusted relay, no knowledge of payload semantics
> 4. **Multi-user layer** (`internal/multimsg/`) — logical presentation only, no new crypto
> 5. **Runtime** (`cmd/`) — shell orchestration, no cryptographic decisions
>
> Each layer is independently auditable and testable. The multi-user layer reuses all existing cryptographic primitives without introducing new ones.
