# KERI & CESR — AI-Oriented Implementation Summary

> This document is an implementation-focused summary of the **Key Event Receipt Infrastructure (KERI)** and **Composable Event Streaming Representation (CESR)** specifications.
> It is written for AI-assisted development and library implementation purposes.

---

# Part 1 — KERI (Key Event Receipt Infrastructure)

## 1. Core Concept

KERI is an event-sourced, cryptographically verifiable identifier system.

An identifier (AID) is controlled by a **Key Event Log (KEL)**.
The KEL is an append-only sequence of events.
Each event:

- Is self-addressing (contains its own digest)
- References the previous event
- Is signed by authorized keys

KERI provides:

- Self-certifying identifiers
- Key rotation
- Threshold signing
- Delegation (advanced)
- Witnessing & receipts (advanced)
- Duplicity detection

---

## 2. Fundamental Objects

### 2.1 Autonomic Identifier (AID)

An AID is typically a self-addressing identifier derived from the digest of its inception event.

Types:

- Transferable (supports rotation)
- Non-transferable (no rotation)

### 2.2 Key Event Log (KEL)

An ordered list of events:

```
icp → rot → ixn → rot → ixn → ...
```

Rules:

- Strict sequence number monotonicity
- Each event references prior event digest
- State derived purely from replaying events

---

## 3. Core Event Types

### 3.1 Inception ("icp")

Creates identifier.

Required fields (ordered):

```
[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]
```

Key semantics:

- `v` = version string
- `t` = event type
- `d` = SAID (self-addressing identifier of event)
- `i` = identifier prefix
- `s` = sequence number ("0")
- `kt` = signing threshold
- `k` = current public keys
- `nt` = next threshold
- `n` = next key digests (commitment to future keys)

Security model:

- Forward commitment via `n`

### 3.2 Rotation ("rot")

Rotates keys.

Required fields:

```
[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]
```

Key rules:

- `s = previous.s + 1`
- `p = previous.d`
- New keys must match prior `n` commitment
- Signed by newly exposed keys

### 3.3 Interaction ("ixn")

State-preserving event.

Fields:

```
[v, t, d, i, s, p, a]
```

Rules:

- No key changes
- Signed by current keys

---

## 4. State Machine Model

Identifier state consists of:

```
{
  aid,
  sn,
  lastEventDigest,
  keys,
  threshold,
  nextKeyDigests,
  nextThreshold
}
```

State transitions are deterministic.
Replay of KEL must always yield same state.

---

## 5. Threshold Logic

Initial minimal model:

Numeric threshold only:

```
validSignatures >= threshold
```

Advanced model (later):

- Weighted thresholds
- Fractional thresholds

---

## 6. Self-Addressing Identifier (SAID)

SAID computation:

1. Replace `d` with dummy value
2. Canonical serialize event
3. Hash
4. CESR-encode digest
5. Insert into `d`

Event is self-certifying.

---

## 7. Attachments

A KERI Message = Body + Attachments.

Attachments include:

- Signatures
- Receipts
- Seals

Attachments are CESR self-framing groups.

---

## 8. Duplicity

Duplicity occurs if:

- Two different events share same `(i, s)`

Detection is mandatory in full implementation.

---

## 9. Event Processing Rules

For every event:

1. Validate structure
2. Verify SAID
3. Verify sequence continuity
4. Verify prior digest chaining
5. Verify threshold signatures
6. Apply state transition

---
