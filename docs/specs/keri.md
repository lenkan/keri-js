# KERI — Curated Spec Reference

> Curated reference for the **Key Event Receipt Infrastructure** (KERI) specification, written for AI assistants and human implementers working in this repo. Distilled from the upstream spec, with links back to the source for anything not covered here.

**Upstream:** https://github.com/trustoverip/kswg-keri-specification
**Spec body:** [`spec/spec-body.md`](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md)

This file is the canonical place to look up KERI message structures, event types, and protocol rules when working on `src/core/`, `src/controller/`, and `src/witness/`. For witness-agreement specifics see also [`docs/kawa.md`](../kawa.md).

---

## 1. Concepts

### Tetrad bindings

KERI permanently binds together four things:

1. **KEL** (Key Event Log) — append-only, hash-chained event sequence.
2. **AID** (Autonomic Identifier) — the identifier prefix.
3. **Keypairs** — the controller's signing keys.
4. **Controllers** — the entities holding the private keys.

Bindings persist across rotations because each event is signed by the *currently authorized* keys and references the prior event's digest.

### SCID vs. AID

- **SCID** (Self-Certifying Identifier): a qualified primitive cryptographically derived from a public key. Authority comes from the math, not from a registry. Becomes worthless if the key is compromised — no recovery.
- **AID** (Autonomic Identifier): an SCID + a KEL that supports key rotation. The identifier persists even as keys change. Constructed as a qualified digest of the inception event (or, for single-key cases, the qualified public key itself).

### Pre-rotation

To rotate keys safely, the controller commits at inception (and at every rotation) to **digests of the next-generation public keys** — without revealing the keys themselves.

- Field `n` holds the list of digests of next keys.
- Field `nt` holds the threshold for those next keys.
- On rotation, the new `k` must hash to the values previously committed in `n`.
- The new event commits a fresh `n` for the *next-next* generation.

Security: an attacker who compromises the current signing keys can't forge a rotation, because they don't know the pre-rotated keys (only their digests appear on-chain).

---

## 2. Field labels (compact form)

KERI messages are JSON / CBOR / MGPK field maps. Compact labels are used to keep messages small.

| Label | Title | Notes |
| :---: | --- | --- |
| `v` | Version String | Always first. Encodes protocol genus, version, serialization, and body length. |
| `t` | Message Type | 3-char code: `icp`, `rot`, `ixn`, `dip`, `drt`, `rct`, etc. |
| `d` | Digest / SAID | Self-addressing digest of the block it appears in. |
| `i` | Identifier Prefix | Controller AID (qualified primitive). |
| `s` | Sequence Number | Hex-encoded integer, strictly monotonic. |
| `p` | Prior SAID | Digest of previous event. |
| `kt` | Keys Threshold | Hex int or fractional weight list. |
| `k` | Signing Keys | List of qualified public keys. |
| `nt` | Next Keys Threshold | Same shape as `kt`. |
| `n` | Next Key Digests | List of qualified digests (pre-rotation commitments). |
| `bt` | Backer Threshold (toad) | Hex int. |
| `b` | Backers list | Witness AIDs. |
| `br` | Backers to Remove | Used in `rot` / `drt`. |
| `ba` | Backers to Add | Used in `rot` / `drt`. |
| `c` | Configuration Traits | List of strings (e.g. `"DID"`, `"NB"`). |
| `a` | Anchors / Seals | List of seal field maps. |
| `di` | Delegator AID | Present on delegated inceptions. |

### Ordering rules

- `v` MUST be the first field.
- `t` MUST be a 3-char string.
- `s` MUST be hex, strictly monotonically increasing; inception events use `"0"`.
- `k` MUST NOT be empty for transferable AIDs.
- `n` MAY be empty for non-transferable AIDs.

Implementation: `src/core/key-event.ts`, `src/core/events.ts`.

---

## 3. Event types

### Establishment events

These change the key state. They MUST exist in every KEL.

#### Inception (`icp`)

Creates the AID and initializes key state.

**Field order:** `v t d i s kt k nt n bt b c a`

```json
{
  "v": "KERICAACAAJSONAAKp.",
  "t": "icp",
  "d": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
  "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
  "s": "0",
  "kt": "2",
  "k":  ["...", "...", "..."],
  "nt": "2",
  "n":  ["...", "...", "..."],
  "bt": "3",
  "b":  ["...", "...", "...", "..."],
  "c":  ["DID"],
  "a":  []
}
```

For a self-addressing AID, `i == d`. Both are computed from the inception event with `d` (and `i`, when self-addressing) replaced by a dummy value of the right length, then the result digested and CESR-encoded.

#### Rotation (`rot`)

Rotates keys and/or backers.

**Field order:** `v t d i s p kt k nt n bt br ba c a`

Rules:
- `s = previous.s + 1`
- `p = previous.d`
- `k` MUST hash to the previous event's `n` (each new key's digest matches a previously committed digest).
- Signed under the **new** keys' threshold `kt` AND with the prior key state revealing valid pre-rotated keys.

#### Delegated inception (`dip`)

Same as `icp` but with a `di` field naming the delegator AID. The delegating AID's KEL must contain a seal anchoring this event for it to be valid.

**Field order:** `v t d i s kt k nt n bt b c a di`

#### Delegated rotation (`drt`)

Same as `rot`. Note: `drt` does **not** carry a `di` field — the delegator is inherited from the matching `dip`.

**Field order:** `v t d i s p kt k nt n bt br ba c a`

### Non-establishment events

#### Interaction (`ixn`)

State-preserving. Anchors external data via seals in `a`.

**Field order:** `v t d i s p a`

```json
{
  "v": "KERICAACAAJSONAAE8.",
  "t": "ixn",
  "d": "EDeC...",
  "i": "EPR7...",
  "s": "1",
  "p": "EPR7...",
  "a": [
    { "i": "EHqS...", "s": "0", "d": "EHqS..." }
  ]
}
```

Signed by the **current** keys (no key state change).

#### Receipt (`rct`)

Conveys signatures or seals as attachments to a key event by reference.

**Field order:** `v t d i s`

```json
{
  "v": "KERICAACAAJSONAACT.",
  "t": "rct",
  "d": "EJOnAKXGaSyJ_43kit0V806NNeGWS07lfjybB1UcfWsv",
  "i": "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
  "s": "2"
}
```

The receipt body is just a reference; the signatures are in the attachment group. Receipts are produced by witnesses (transferable signatures use indexed sigs; non-transferable nontrans witnesses use `0B` or `0C` couples).

Implementation: `src/core/key-event.ts`, `src/core/receipt-event.ts`, `src/core/events.ts`.

---

## 4. SAID (Self-Addressing IDentifier)

A SAID is a digest of the very block it lives in. Computation:

1. Replace SAID-bearing fields (`d`, and `i` when self-addressing) with dummy values **of the correct CESR-encoded length** (so the serialized size is stable).
2. Canonically serialize (JSON / CBOR / MGPK as declared by `v`).
3. Hash (default Blake3-256).
4. CESR-encode the digest.
5. Substitute back into `d` (and `i` if self-addressing).

The version string `v` carries the body length, so it must also be sized before hashing — fill with the final length using a placeholder that has the same character count.

Implementation: `src/core/said.ts`.

---

## 5. Seals

Seals appear in the `a` field of events. They cryptographically bind external data into the KEL.

| Seal | Fields | Used for |
| --- | --- | --- |
| **Digest** | `d` | Generic digest commitment. |
| **Merkle root** | `rd` | Root of a Merkle tree — compact commitment to many items. |
| **Source event** | `s`, `d` | Sequence + SAID of an event in an *implied* AID's KEL (delegations, credential issuance). |
| **Key event** | `i`, `s`, `d` | Explicit AID + sequence + SAID of an event in another KEL. |
| **Latest establishment** | `i` | Reference to the latest establishment event of the named AID. |
| **Registrar backer** | (registrar-specific) | Used by ACDC TEL registrars. |

The `a` field on `ixn` events is the primary anchoring mechanism for credentials, exchanges, and delegations.

---

## 6. State machine

Replaying a KEL from `icp` forward produces deterministic state:

```ts
{
  aid: string,                 // i field of icp
  sn: number,                  // current sequence number
  lastEventDigest: string,     // d of last accepted event
  keys: string[],              // current k
  threshold: Threshold,        // current kt
  nextKeyDigests: string[],    // current n
  nextThreshold: Threshold,    // current nt
  backers: string[],           // current b
  backerThreshold: number      // current bt
}
```

Per-event processing (`src/core/verify.ts`):

1. Validate structure (required fields, types, ordering).
2. Verify SAID — recompute and compare `d`.
3. Verify sequence continuity — `s == prev.s + 1`.
4. Verify prior digest chaining — `p == prev.d`.
5. Verify threshold of valid signatures over the canonical bytes.
6. For rotations: verify each new key's digest appears in prior `n`.
7. Apply state transition.

---

## 7. Duplicity

Duplicity is when **two distinct events share the same `(i, s)`**. Witnesses follow a **first-seen** policy: receipt the first verified event at a given sequence number, ignore later conflicting versions. This is the basis of KAWA (see [`docs/kawa.md`](../kawa.md)).

A controller proven duplicitous is permanently distrusted: any verifier observing two valid-but-conflicting events at the same `(i, s)` MUST refuse the AID.

---

## 8. Witnesses & receipts (KAWA in brief)

- Controller designates `N` witnesses in `b` and a threshold `bt` (toad) at inception.
- For each new event, controller broadcasts to witnesses; each returns an `rct` with a witness signature.
- Controller collects ≥ `bt` receipts and re-broadcasts so every witness holds every other witness's receipt.
- Verifiers check that an event has ≥ `bt` valid witness signatures from `b` to consider it confirmed.

Constraint for immunity to duplicity attacks: `M > F`, where `M = bt` and `F = N − M` is the maximum tolerated faulty/unavailable witnesses.

Implementation: `src/witness/`, `src/core/kawa.ts`, `src/core/witness-client.ts`.

Detailed protocol: [`docs/kawa.md`](../kawa.md).

---

## 9. Where things live in this repo

| Concern | File(s) |
| --- | --- |
| Event construction & types | `src/core/key-event.ts`, `src/core/events.ts` |
| KEL replay & verification | `src/core/key-event-log.ts`, `src/core/verify.ts` |
| Signing | `src/core/sign.ts`, `src/core/keys.ts` |
| SAID computation | `src/core/said.ts` |
| Threshold logic | `src/core/threshold.ts` |
| Receipts | `src/core/receipt-event.ts` |
| Witness coordination | `src/core/kawa.ts`, `src/core/witness-client.ts`, `src/witness/` |
| Routed envelopes | `src/core/routed-event.ts` |
| Mailbox / endpoints | `src/core/mailbox-client.ts`, `src/core/endpoint-discovery.ts` |
| Credentials (ACDC-adjacent) | `src/core/credential.ts`, `src/core/credential-event.ts`, `src/core/registry-event.ts` |
| Identifier controller | `src/controller/` |

---

## 10. When to consult the upstream spec

Use the upstream spec directly when:

- Implementing a new event type or message family beyond the core seven (`icp`, `rot`, `ixn`, `dip`, `drt`, `rct`, plus query/reply variants).
- Looking up exact rules for **fractional / weighted thresholds** in `kt` / `nt`.
- Implementing **delegation** end-to-end (the spec has a full sequence diagram for `dip` anchoring).
- Reasoning about **configuration traits** (`c` field): `NB` (no-backers), `DID`, etc.
- Cross-referencing exact CESR codes used in attachments — see also [`./cesr.md`](./cesr.md).

Direct links:
- Foundational concepts: [§ "KERI foundational overview"](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#keri-foundational-overview)
- Field labels & ordering: [§ "KERI data structures and labels"](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#keri-data-structures-and-labels)
- Seals: [§ "Seals"](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#seals)
- Key event messages: [§ "Key event messages"](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#key-event-messages)
- Receipt messages: [§ "Receipt Messages"](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#receipt-messages)
