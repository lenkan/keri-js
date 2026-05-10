# ACDC — Curated Spec Reference

> Curated reference for the **Authentic Chained Data Container** (ACDC) specification, written for AI assistants and human implementers working in this repo. Distilled from the upstream spec, with links back to the source for anything not covered here.

**Upstream:** https://github.com/trustoverip/kswg-acdc-specification
**Spec body:** [`spec/spec-body.md`](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md)

This file is the canonical place to look up ACDC structure, variants, sections (schema/attribute/aggregate/edge/rule), IPEX exchange messages, and TEL registry events when working on credential code in `src/core/`. It builds on `cesr.md` (encoding) and `keri.md` (KELs, AIDs, seals).

---

## 1. What an ACDC is

An ACDC is a **nested ordered field map** representing a verifiable credential or container. It supports decentralized trust across domains by combining:

- **AIDs** — Issuer (and optionally Issuee) identifiers, each backed by a KERI KEL.
- **SAIDs** — every block's identity is its own digest, enabling hierarchical commitments.
- **JSON Schema (2020-12)** — every ACDC has a schema; ACDCs follow the **type-is-schema** principle (no separate type field — the schema *is* the type).
- **Composable variants** — one schema permits compact, expanded, public, private, and metadata variants without re-issuing.

ACDCs may be chained via **edges** (each edge points to another ACDC's SAID), forming fragments of a globally distributed, verifiable property graph.

Implementation: `src/core/credential.ts`, `src/core/credential-event.ts`, `src/core/registry-event.ts`.

---

## 2. Top-level fields

| Label | Title | Description |
| :---: | --- | --- |
| `v` | Version String | Format `ACDCMmmGggKKKKSSSS.` — protocol, version, CESR genus version, serialization, size, terminator. |
| `t` | Message Type | 3-char message type. Default for ACDCs is `acm`. |
| `d` | Message SAID | Self-referential digest of the enclosing map. |
| `u` | UUID | Salty nonce for blinding (private/metadata variants). |
| `i` | Issuer AID | KERI-controlled issuer. |
| `rd` | Registry SAID | TEL registry initializing event SAID (issuance/revocation state). |
| `s` | Schema | SAID of, or full, JSON Schema block. |
| `a` | Attribute | SAID of, or full, attribute block (partial disclosure). |
| `A` | Attribute Aggregate | Aggregate of selectively disclosable attribute blocks. |
| `e` | Edge | SAID of, or full, edge block. |
| `r` | Rule | SAID of, or full, rule block (Ricardian contract). |

**Field ordering (when present):** `[v, t, d, u, i, rd, s, a, A, e, r]`.

**Required:** `[v, d, i, s]`.

**Mutually exclusive:** an ACDC MUST NOT have both a non-empty `a` and a non-empty `A`.

### Other reserved labels (used at non-top levels)

| Label | Use |
| :---: | --- |
| `dt` | ISO-8601 datetime (issuer-local clock, microseconds + UTC offset). |
| `n` | Node — SAID of a far-node ACDC at the end of an edge. |
| `o` | Operator — m-ary on edge-groups, unary on edges. |
| `w` | Weight — for weighted edges/edge-groups. |
| `l` | Legal language — Ricardian contract clause text. |
| `cargo` | Opaque embedded payload inside attribute blocks. |

---

## 3. Variants

### Most compact form SAID

The canonical SAID of an ACDC is computed bottom-up: SAID each leaf block on its fully expanded form, replace it with its SAID in the enclosing block, recurse to the trunk. This guarantees one and only one SAID per ACDC, regardless of which `oneOf` variant is on the wire.

This is what makes Graduated Disclosure work: the verifier receives any variant and can verify its SAID against parts of the hash tree without seeing the rest.

### Compact ACDC

`s`, `a`, `e`, `r` are SAIDs (digests) rather than expanded blocks. `A` uses its own aggregate digest in compact form.

### Public ACDC

No top-level `u` field. The top-level SAID is **discoverable** from the schema via rainbow/dictionary attack — treat as non-confidential.

### Private ACDC

Top-level `u` field with sufficient entropy. The SAID becomes a blinded commitment — the contents can't be discovered from `(schema, d)` alone. Required for selective/partial disclosure.

### Metadata ACDC

Top-level `u` field is **present but empty**. Allows the discloser to commit to schema/issuer/edges/rules **without** correlating to the actual ACDC's SAID. Used to negotiate contractual terms (see Chain-Link Confidentiality) before disclosure.

### Bespoke ACDC

Disclosure-specific ACDC issued by the discloser, augmenting an existing ACDC by chaining via an edge. Adds context-specific rules (anti-assimilation clauses, named issuee, etc.) without modifying the underlying credential.

---

## 4. Sections

### 4.1 Schema (`s`)

- **Dialect:** JSON Schema 2020-12.
- **Type-is-schema:** the schema's SAID functions as the credential's type. No `type` field on ACDCs.
- **Static / immutable:** schemas MUST be self-contained and fixed; the schema's `$id` MUST contain its SAID. Dynamic schema references are forbidden (prevents semantic-malleability attacks).
- **Composable:** uses `oneOf` / `anyOf` to permit compact/expanded variants without re-issuing.

### 4.2 Attribute (`a`)

The credential's "payload" data. Reserved labels inside the attribute block:

| Label | Use |
| :---: | --- |
| `d` | SAID of the attribute block. |
| `u` | UUID (blinding factor). |
| `i` | Issuee AID (presence makes it **targeted**). |
| `rd` | Per-credential registry SAID (alternative to top-level `rd`). |
| `dt` | Issuance datetime. |
| `cargo` | Opaque payload. |

**Targeted vs untargeted:**
- **Targeted** — `i` (Issuee) present. Binds credential to a specific party; enables Issuer-To-Issuee chains.
- **Untargeted** — no `i`. "To whom it may concern" attestation; authorship without entitlement.

### 4.3 Aggregate (`A`)

Used for **selective disclosure** of independent attribute blocks.

- Each member is a blinded attribute block with its own `d` (SAID) and `u` (UUID).
- **AGID** (Aggregate ID): cryptographic digest of the ordered list `[placeholder, SAID₁, …, SAIDₙ]` — the placeholder is replaced with the computed digest, producing a self-referential aggregate digest.
- **Inclusion proof** for one block: verify (a) the disclosed block's SAID, (b) its membership in the SAID list, (c) the recomputed AGID, (d) the issuer's KEL seal on the top-level ACDC SAID.
- Disclosing one block leaks nothing about the others (they remain blinded by their own UUIDs).

### 4.4 Edge (`e`)

Edges chain ACDCs into a property graph. The edge section is itself a tree of **edge-groups** (m-ary nodes) with **edges** (leaves) at the tips.

#### Edge-group

| Label | Use |
| :---: | --- |
| `d` | Optional SAID. |
| `u` | Optional UUID. |
| `o` | Optional m-ary operator over child edges/groups. |
| `w` | Optional weight (only valid in nested groups, not the top-level edge section). |

**M-ary operators** (default `AND` if `o` is missing):

| Operator | Meaning |
| --- | --- |
| `AND` | All members must be valid. |
| `OR` | At least one member must be valid. |
| `NAND` | NOT all members valid. |
| `NOR` | All members must be invalid. |
| `AVG` | Arithmetic average of a member property defined by schema/EGF. |
| `WAVG` | Weighted average using `w` fields. |

#### Edge

| Label | Use |
| :---: | --- |
| `d` | Optional SAID of the edge block. |
| `u` | Optional UUID (presence makes it a **private edge**). |
| `n` | **Required.** SAID of the far-node ACDC. |
| `s` | Optional schema constraint on the far node. |
| `o` | Optional unary operator(s). |
| `w` | Optional weight. |

**Field order when present:** `[d, u, n, s, o, w]`.

**Unary operators** (defaults: `I2I` for targeted far nodes, `NI2I` for untargeted):

| Operator | Meaning |
| --- | --- |
| `I2I` | Issuer-To-Issuee — this ACDC's issuer MUST equal the far node's issuee. (default for targeted far nodes) |
| `NI2I` | Not-Issuer-To-Issuee — relaxes `I2I`. (default for untargeted far nodes) |
| `DI2I` | Delegated-Issuer-To-Issuee — this ACDC's issuer MUST be the far node's issuee or a delegated AID thereof. |
| `NOT` | Inverts validity of the far node. |

#### Compact / simple-compact edge forms

- **Compact edge**: replace edge block with its SAID (requires `d`).
- **Simple compact edge**: edge has only `n` — value becomes the far-node SAID directly (always public).

### 4.5 Rule (`r`)

Ricardian contracts: human- and machine-readable legal language tied to the ACDC by digest.

#### Rule-group

| Label | Use |
| :---: | --- |
| `d` | Optional SAID. |
| `u` | Optional UUID. |
| `l` | Optional legal language (group-level prelude). |

**Field order when present:** `[d, u, l]`.

#### Rule

A leaf rule block has a `d`, optional `u`, and an `l` (legal text). Compact and simple-compact rule forms parallel the edge forms.

Common rule labels: `Assimilation` (anti-assimilation clause), `Purpose`, etc. — these are application-defined and constrained by the schema.

---

## 5. IPEX (Issuance and Presentation Exchange)

A uniform exchange protocol for both issuance and presentation, modeled as **disclosure from a Discloser to a Disclosee**. Carried over KERI **routed exchange (`exn`) messages**; the `r` route field selects the IPEX message type.

### Route table

| Sender | Route | Initiates? | Contents | Purpose |
| :---: | :---: | :---: | --- | --- |
| Disclosee | `apply` | Y | Schema/SAID, attribute label list, aggregate label list, signature | Defines wanted disclosure |
| Discloser | `spurn` | N | — | Rejects `apply` |
| Discloser | `offer` | Y | Metadata ACDC (or SAID), schema, partial disclosure, signature | Proposes acceptable disclosure |
| Disclosee | `spurn` | N | — | Rejects `offer` |
| Disclosee | `agree` | N | Signature/seal on `offer` | Accepts `offer` (locks in rules) |
| Discloser | `spurn` | N | — | Rejects `agree` |
| Discloser | `grant` | Y | Full or selective ACDC, signature | Discloses agreed-to content |
| Disclosee | `admit` | N | Signature/seal on `grant` | Confirms receipt |

Either party may initiate (`apply` or `offer`). `spurn` terminates a stage at any point. The `agree` step is the **chain-link confidentiality** point: the disclosee accepts the rule section before content is revealed.

### Issuer commitment rules

- The issuer MUST sign or seal the **SAID of the most-compact-form variant**.
- Because all variants share the same top-level structure, that one commitment verifies any later variant's top-level sections.
- **Proof of Issuance (PoI):** disclose the most-compact SAID + issuer's signature/seal on it.
- **Proof of Disclosure (PoD):** disclose the SAD of the most-compact variant, then recursively expand nested blocks as needed.

---

## 6. TEL registries (issuance/revocation state)

ACDC dynamic state (issued, revoked, transferred…) lives in a **Transaction Event Log** (TEL), a hash-chained log of events sealed (anchored) into the controller's KEL via seals.

Sealing a TEL event in the KEL binds the TEL to the **key state at the sealing event** — verifiability persists across later key rotations. TEL events themselves don't need to be signed: the seal in the (signed) KEL event is the commitment.

Seal serialization (JSON):

```json
{ "s": "3", "d": "ELvaU6Z-..." }
```

CESR seal couple count code: `-T##` or `--T#####`.

### Registry message types

| Type | Name | Purpose |
| :---: | --- | --- |
| `rip` | Registry Inception | Initializes the registry. |
| `bup` | Blindable Update | Blinded transaction state update. |
| `upd` | Update | Non-blindable (public) state update. |

### Top-level fields

| Label | Use |
| :---: | --- |
| `v`, `t`, `d`, `u`, `i` | Standard. |
| `rd` | Registry SAID. |
| `n` | Sequence number (hex). |
| `p` | Prior event SAID. |
| `dt` | Datetime. |
| `b` | Blinded attribute block SAID (`bup` only). |
| `ta` | Transaction target ACDC SAID (`upd` only). |
| `ts` | Transaction state (`upd` only — e.g. `issued`, `revoked`). |

### Field orderings

- `rip`: `[v, t, d, u, i, n, dt]` — `n = "0"`.
- `bup`: `[v, t, d, rd, n, p, dt, b]`.
- `upd`: `[v, t, d, rd, n, p, dt, ta, ts]`.

A registry MAY mix blinded and public updates over its lifetime.

Implementation: `src/core/registry-event.ts`.

---

## 7. Selective vs partial vs graduated disclosure

| Mechanism | Section | What's revealed |
| --- | --- | --- |
| **Partial** | Attribute (nested compaction) | Some nested attribute blocks revealed via SAID expansion; others stay compact. |
| **Selective** | Aggregate | Individual blinded attribute blocks proven against the AGID; others stay blinded. |
| **Graduated** | Both | Staged: metadata → compact → partial → full, gated by `agree` in IPEX. |
| **Chain-Link Confidentiality** | Rule | Disclosee must accept rule terms before content disclosure. |
| **Contractually Protected** | Whole exchange | Rule-section terms enforced via signed `agree`. |

---

## 8. Where things live in this repo

| Concern | File(s) |
| --- | --- |
| ACDC construction & validation | `src/core/credential.ts` |
| Credential events (issuance) | `src/core/credential-event.ts` |
| TEL registry events (`rip` / `bup` / `upd`) | `src/core/registry-event.ts` |
| Routed `exn` envelopes (IPEX carriers) | `src/core/routed-event.ts` |
| Mailbox / endpoints (presentation transport) | `src/core/mailbox-client.ts`, `src/core/endpoint-discovery.ts` |
| SAID computation | `src/core/said.ts` |
| KERI seals | see [`./keri.md`](./keri.md) §5 |

---

## 9. When to consult the upstream spec

Use the upstream spec directly when:

- Building **selective-disclosure aggregate proofs** — exact AGID composition algorithm and JSON Schema layout matter.
- Implementing **bulk-issued private ACDCs** — see Annex section.
- Adding **CESR-native ACDC serialization** — different from JSON; needs the CESR genus codes.
- Reading **bound blinded attribute** semantics (`bn`, `bd` fields binding a blinded TEL event to a specific issuee key state).
- Writing **edge subschemas** with `oneOf` compositions for compact/expanded variants — there are subtle rules about `oneOf` ordering for SAID computation.

Direct links:
- Top-level fields & variants: [§ "ACDC Structure"](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#acdc-structure)
- Most compact form SAID algorithm: [§ "Most compact form SAID"](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#most-compact-form-said)
- Edge section (operators, edge-groups): [§ "Edge Section"](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#edge-section)
- Aggregate / selective disclosure: [§ "Aggregate Section"](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#aggregate-section)
- IPEX: [§ "Issuance and Presentation Exchange (IPEX)"](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#issuance-and-presentation-exchange-ipex)
- TEL registries: [§ "Transaction event logs (TELs) as ACDC state registries"](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#transaction-event-logs-tels-as-acdc-state-registries)
