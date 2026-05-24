# KERI — Curated Spec Reference

> Implementation-focused reference for the **Key Event Receipt Infrastructure** (KERI) specification, as implemented in this repo.

**Upstream:** https://github.com/trustoverip/kswg-keri-specification ([spec body](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md))

This codebase implements **KERI v1** (legacy version strings). Witness-agreement specifics live in [`../kawa.md`](../kawa.md).

## 1. Where things live

| Concern | File(s) |
| --- | --- |
| Event construction (`icp`/`rot`/`ixn`/`dip`/`drt`) | `src/core/key-event.ts` |
| Event encoding / SAID prep | `src/core/events.ts` |
| KEL replay, sequence/prior-digest validation, state transitions, delegator-anchor verification | `src/core/key-event-log.ts` |
| Signature & threshold verification | `src/core/verify.ts` |
| Signing | `src/core/sign.ts`, `src/core/keys.ts` |
| SAID computation | `src/core/said.ts` |
| Threshold logic | `src/core/threshold.ts` |
| Receipts (`rct`) | `src/core/receipt-event.ts` |
| Routed envelopes (`qry`/`rpy`/`exn`) | `src/core/routed-event.ts` |
| Witness coordination (KAWA) | `src/core/kawa.ts`, `src/core/witness-client.ts`, `src/witness/` |
| Mailbox / endpoints | `src/core/mailbox-client.ts`, `src/core/endpoint-discovery.ts` |
| Identifier controller | `src/controller/` |
| Credentials (ACDC-adjacent) | `src/core/credential.ts`, `src/core/credential-event.ts`, `src/core/registry-event.ts` |

**Implementation status:** establishment events implemented are `icp`, `rot`, `ixn`, `rct`, `dip`, and `drt`. Delegated events are parsed by `KeyEventLog`, builders (`delegatedIncept` / `delegatedRotate`) live in `key-event.ts`, and the controller exposes `Controller.delegatedIncept`. When the delegator's KEL is supplied via `AppendOptions.delegator`, dip/drt anchor seals are verified against it; `KeyEventLog.parse` (and `fromMessages`) does this automatically for multi-AID streams by selecting the leaf AID and chaining the delegator log bottom-up.

## 2. Concepts

### Tetrad

KERI permanently binds: **KEL** (key event log) ↔ **AID** (autonomic identifier) ↔ **keypairs** ↔ **controllers**. Bindings persist across rotations because each event is signed by the currently authorised keys and references the prior event's digest.

### SCID vs AID

- **SCID** — qualified primitive cryptographically derived from a public key. Authority comes from the math; no recovery if the key is compromised.
- **AID** — SCID + KEL that supports rotation. The identifier persists as keys change.

### Pre-rotation

To rotate keys safely, the controller commits at inception (and at every rotation) to **digests of the next-generation public keys** without revealing the keys themselves.

- `n` — list of digests of next keys.
- `nt` — threshold for those next keys.
- On rotation, the new `k` must hash to the values previously committed in `n`; the new event commits a fresh `n` for the next-next generation.

An attacker who compromises current signing keys can't forge a rotation because the pre-rotated keys are not on-chain (only their digests are).

## 3. Event types

Compact field labels:

| Label | Meaning |
| :---: | --- |
| `v` | Version string (always first) |
| `t` | 3-char message type |
| `d` | SAID of the enclosing block |
| `i` | Identifier prefix / AID |
| `s` | Sequence number (hex) |
| `p` | Prior event SAID |
| `kt` / `k` | Signing threshold / keys |
| `nt` / `n` | Next-keys threshold / digests |
| `bt` / `b` | Backer (witness) threshold / list |
| `br` / `ba` | Backers to remove / add (rotation) |
| `c` | Configuration traits (`NB`, `DID`, …) |
| `a` | Anchors / seals |
| `di` | Delegator AID (`dip` only) |

### Inception (`icp`)

Field order: `[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]` (`s = "0"`).

For self-addressing AIDs `i == d`. Both are computed by replacing them with same-length dummy values, serialising, hashing, then substituting the CESR-encoded digest back.

`isTransferable` (`key-event.ts:93`) determines `labels` for SAID computation: non-transferable inceptions only saidify `d`, transferable inceptions saidify both `d` and `i`.

### Rotation (`rot`)

Field order: `[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]`.

Rules: `s = previous.s + 1`, `p = previous.d`. New `k` must hash to the previous event's `n`. Signed under the **new** keys' threshold.

### Interaction (`ixn`)

Field order: `[v, t, d, i, s, p, a]`.

State-preserving — anchors external data via seals in `a`. Signed by current keys.

### Receipt (`rct`)

Field order: `[v, t, d, i, s]`.

Body is just a reference to a key event; the signatures are attached via CESR groups. Witness receipts use the `NonTransReceiptCouples` group (count code `C` in v1, `M` in v2) carrying `(prefix, signature)` couples; the signature primitive is Ed25519 (`0B`) or ECDSA-256k1 (`0C`). Transferable signers use indexed signatures instead.

### Delegation (`dip` / `drt`)

`dip` is `icp` plus a `di` field naming the delegator AID. `drt` mirrors `rot` and inherits the delegator from its matching `dip`. The delegator's KEL must carry an event (typically an `ixn`) whose `a` field anchors the delegated event via a key-event seal `{i, s, d}` — `i` being the delegate's AID, `s`/`d` the delegated event's sequence and SAID.

Two attachment groups can carry a *hint* about which delegator event holds the anchor:

| Group | Fields | Meaning |
| --- | --- | --- |
| `SealSourceCouples` | `(snu, digest)` | Delegator event's sequence + SAID. Used when delegator is implied. |
| `SealSourceTriples` | `(prefix, snu, digest)` | Same, plus explicit delegator prefix. Filtered on `prefix == body.di`. |

`KeyEventLog.append` (via `verifyDelegationAnchor` in `key-event-log.ts`) treats every attached hint as required — all referenced delegator events must exist and must contain a matching seal. If no hint is attached, the verifier scans the delegator's KEL for any event whose `a` field anchors the dip/drt (the wire-form keripy uses when transmitting only the delegator KEL). Verification is **opt-in**: callers must pass `AppendOptions.delegator`; `KeyEventLog.from(storage.getKeyEvents(...))` does not re-verify by default.

## 4. SAID

A SAID is a digest of the very block it lives in. Computation:

1. Replace SAID-bearing fields (`d`, and `i` when self-addressing) with **dummy values of the correct CESR-encoded length** so the serialised size is stable.
2. Canonically serialise (JSON / CBOR / MGPK as declared by `v`).
3. Hash (default Blake3-256).
4. CESR-encode the digest.
5. Substitute back.

The version string `v` carries the body length, so it must also be size-stable before hashing. `encodeEvent` in `events.ts` handles this by sizing fields with `"#"` placeholders before calling `saidify`.

## 5. Seals

Seals appear in the `a` field of events and bind external data into the KEL.

| Seal | Fields | Used for |
| --- | --- | --- |
| Digest | `d` | Generic commitment |
| Merkle root | `rd` | Compact commitment to many items |
| Source event | `s`, `d` | Sequence + SAID in an implied AID's KEL (delegations, credential issuance) |
| Key event | `i`, `s`, `d` | Explicit AID + sequence + SAID in another KEL |
| Latest establishment | `i` | Reference to latest establishment event of `i` |

`a` on `ixn` events is the primary anchor for credentials and exchanges.

## 6. Per-event processing

Replaying a KEL from `icp` forward yields deterministic state. Per-event flow lives in `KeyEventLog.append` (`src/core/key-event-log.ts`):

1. Validate structure and event type (`icp`/`ixn`/`rot`/`dip`/`drt`).
2. Verify SAID — recompute and compare `d`.
3. For non-inception events, verify sequence continuity (`s == prev.s + 1`) and prior digest chaining (`p == prev.d`).
4. Verify threshold of valid signatures (delegated to `verify.ts`).
5. For rotations, verify each new key's digest appears in prior `n`.
6. For `dip`/`drt` with a delegator KEL in scope, verify the delegator-anchor seal (see Delegation above).
7. Apply state transition.

Resulting state shape:

```ts
{
  identifier: string,           // i of icp
  sequenceNumber: number,
  lastEventDigest: string,
  signingKeys: string[],
  signingThreshold: Threshold,
  nextKeyDigests: string[],
  nextThreshold: Threshold,
  backers: string[],
  backerThreshold: number
}
```

## 7. Duplicity

Duplicity = two distinct events sharing `(i, s)`. Witnesses follow a **first-seen** policy: receipt the first verified event at a sequence number, ignore later conflicting versions. The basis of KAWA — see [`../kawa.md`](../kawa.md).

A controller proven duplicitous is permanently distrusted: any verifier observing two valid-but-conflicting events at the same `(i, s)` MUST refuse the AID.

## 8. Witnesses (KAWA in brief)

- Controller designates `N` witnesses in `b` and a threshold `bt` (toad) at inception.
- For each new event, controller broadcasts to witnesses; each returns an `rct`.
- Controller re-broadcasts so every witness holds every other witness's receipt.
- Verifiers require ≥ `bt` valid witness signatures from `b` for confirmation.

Constraint for duplicity-immunity: `M > F`, `M = bt`, `F = N − M`.

Implementation notes (deviations from spec) live in [`../kawa.md`](../kawa.md).

## 9. When to consult the upstream spec

- Implementing fractional / weighted thresholds (`kt` / `nt` non-integer cases).
- Multisig delegated rotation (`drt` with `kt`/`nt` other than `"1"`) — `delegatedRotate` hardcodes single-sig thresholds.
- Configuration traits (`c` field) beyond `NB` / `DID`.
- New event types not in the core (`icp`/`rot`/`ixn`/`rct`/`qry`/`rpy`/`exn`).

Direct links:
- [Foundational concepts](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#keri-foundational-overview)
- [Field labels & ordering](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#keri-data-structures-and-labels)
- [Seals](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#seals)
- [Key event messages](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#key-event-messages)
- [Receipt messages](https://github.com/trustoverip/kswg-keri-specification/blob/main/spec/spec-body.md#receipt-messages)
