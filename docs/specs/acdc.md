# ACDC — Curated Spec Reference

> Implementation-focused reference for the **Authentic Chained Data Container** (ACDC) specification, as implemented in this repo.

**Upstream:** https://github.com/trustoverip/kswg-acdc-specification ([spec body](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md))

This codebase implements **ACDC v1** (legacy version strings, `vcp`/`iss`/`rev` TEL events). The v2 spec changes several field labels (`rd`/`ri`, `A` aggregate, `bup` blindable updates, `rip`/`upd` TEL types) and adds selective disclosure — those features are **not implemented**. Where this doc references v2 it is flagged.

Builds on [`./cesr.md`](./cesr.md) (encoding) and [`./keri.md`](./keri.md) (KELs, AIDs, seals).

## 1. Where things live

| Concern | File(s) |
| --- | --- |
| ACDC construction (`createCredential`) | `src/core/credential.ts` |
| Credential events (`iss` / `rev`) | `src/core/credential-event.ts` |
| TEL registry events (`vcp`) | `src/core/registry-event.ts` |
| Routed `exn` envelopes (IPEX carriers) | `src/core/routed-event.ts` |
| SAID computation | `src/core/said.ts` |
| KERI seals | see [`./keri.md`](./keri.md) §5 |

## 2. What an ACDC is

An ACDC is a **nested ordered field map** representing a verifiable credential or container. It combines:

- **AIDs** — Issuer (and optionally Issuee) identifiers, each backed by a KERI KEL.
- **SAIDs** — every block's identity is its own digest.
- **JSON Schema (2020-12)** — every ACDC has a schema; **type-is-schema** (no separate type field — the schema *is* the type).

ACDCs may be chained via **edges** (each edge points to another ACDC's SAID), forming fragments of a verifiable property graph.

## 3. ACDC body (this implementation)

`createCredential` (`src/core/credential.ts`) emits:

```ts
{
  v: string,    // ACDC version string (legacy v1)
  d: string,    // SAID of the ACDC
  u?: string,   // Salty nonce (optional; presence makes it a private ACDC)
  i: string,    // Issuer AID
  ri: string,   // Registry SAID (registry inception's `i`)
  s: string,    // Schema SAID
  a: {          // Attribute block (selectively-disclosable claims)
    d: string,  //   SAID of the attribute block
    i?: string, //   Issuee AID (presence makes it targeted)
    dt?: string,
    ...claims
  },
  r: {          // Rule block (Ricardian terms)
    d: string,
    ...rules
  },
  e?: {         // Edge block (links to other ACDCs)
    d: string,
    ...edges
  }
}
```

**Field order on the wire:** `[v, d, (u), i, ri, s, a, r, (e)]`. Required: `v, d, i, ri, s, a, r`.

### Notes vs upstream spec

- v2 renames `ri` → `rd` (registry SAID at top level) and uses `t: "acm"` for the message type. v1 has no `t` on the credential body.
- v2 adds a top-level `A` (aggregate) field for selective disclosure, mutually exclusive with `a`. **Not implemented.**
- The `a` block in v1 doubles as the credential subject (its `i` is the Issuee). Targeted/untargeted distinction is identical to v2.

### Public vs private

- **Public ACDC** — no top-level `u`. The SAID is discoverable from the schema by rainbow attack — treat as non-confidential.
- **Private ACDC** — top-level `u` with sufficient entropy. Required for partial-disclosure flows; the SAID becomes a blinded commitment.

## 4. Sections

### 4.1 Schema (`s`)

- **Dialect:** JSON Schema 2020-12.
- **Type-is-schema:** schema's SAID is the credential's type.
- **Static / immutable:** schemas are self-contained; the schema's `$id` MUST contain its SAID. Dynamic schema references are forbidden (prevents semantic-malleability).

### 4.2 Attribute (`a`) — credential subject

Reserved labels inside the attribute block:

| Label | Use |
| :---: | --- |
| `d` | SAID of the attribute block |
| `u` | UUID (blinding factor) |
| `i` | Issuee AID (presence makes it **targeted**) |
| `dt` | Issuance datetime (ISO-8601, microseconds + UTC offset) |

**Targeted vs untargeted:**
- **Targeted** — `i` (Issuee) present. Binds credential to a specific party; enables Issuer-To-Issuee chains.
- **Untargeted** — no `i`. "To whom it may concern" attestation.

### 4.3 Edge (`e`)

Edges chain ACDCs into a property graph. Each edge points at another ACDC by SAID.

| Label | Use |
| :---: | --- |
| `d` | SAID of the edge block |
| `n` | **Required.** SAID of the far-node ACDC |
| `s` | Optional schema constraint on the far node |
| `o` | Optional unary operator (`I2I`, `NI2I`, `DI2I`, `NOT`) |

`I2I` (Issuer-To-Issuee) is the default for targeted far nodes; `NI2I` for untargeted. Operator semantics and m-ary edge-groups (`AND`/`OR`/`AVG`/…) are spec-defined; this implementation does not enforce operator semantics on validation, it just shapes the JSON.

### 4.4 Rule (`r`) — Ricardian contract

Human- and machine-readable legal language tied to the ACDC by digest. Each rule block has a `d` and application-defined `l` legal text. Common labels: `Assimilation`, `Purpose`, etc.

## 5. TEL registries (issuance / revocation)

ACDC dynamic state lives in a **Transaction Event Log** (TEL) — a hash-chained log sealed (anchored) into the controller's KEL via seals. Sealing a TEL event in the KEL binds the TEL to the **key state at the sealing event**, so verifiability persists across later rotations. The TEL events themselves are not signed — the seal in the (signed) KEL event is the commitment.

### v1 event types (this implementation)

| Type | Purpose | File |
| :---: | --- | --- |
| `vcp` | Registry inception | `src/core/registry-event.ts` |
| `iss` | Credential issuance | `src/core/credential-event.ts` |
| `rev` | Credential revocation | `src/core/credential-event.ts` |

### Registry inception (`vcp`)

```ts
{ v, t: "vcp", d, i, ii, s: "0", c, bt, b, n }
```

- `i` — Registry SAID (becomes the `ri` referenced from credentials).
- `ii` — Issuer AID (the controller that owns the registry).
- `c` — Configuration traits. Default `["NB"]` (no backers).
- `n` — Nonce (random salt; required for SAID stability).

### Issuance (`iss`)

```ts
{ v, t: "iss", d, i, s: "0", ri, dt }
```

- `i` — **Credential SAID** (not the issuer). The TEL key for this credential's lifecycle.
- `s` — Always `"0"` for an issuance event.
- `ri` — Registry SAID.

### Revocation (`rev`)

```ts
{ v, t: "rev", d, i, s: "1", ri, p, dt }
```

- `s` — `"1"` (the revocation always follows issuance at sn 1).
- `p` — Prior issuance event SAID.

### Not implemented (v2 only)

- `rip` (registry inception, replaces `vcp`)
- `bup` (blindable update — selective-disclosure-aware state changes)
- `upd` (non-blindable public update)
- AGID-based selective-disclosure aggregate proofs
- Bound blinded attribute (`bn`/`bd`) semantics

## 6. IPEX (Issuance and Presentation Exchange)

A uniform exchange protocol for both issuance and presentation, modeled as **disclosure from a Discloser to a Disclosee**. Carried over KERI **routed exchange (`exn`) messages** (`src/core/routed-event.ts`); the `r` route field selects the IPEX message type.

| Sender | Route | Purpose |
| :---: | :---: | --- |
| Disclosee | `apply` | Defines wanted disclosure |
| Discloser | `offer` | Proposes acceptable disclosure (metadata ACDC or partial) |
| Disclosee | `agree` | Accepts `offer` (locks in rules) |
| Discloser | `grant` | Discloses agreed-to content |
| Disclosee | `admit` | Confirms receipt |
| either | `spurn` | Rejects the previous step |

Either party may initiate (`apply` or `offer`). The `agree` step is the **chain-link confidentiality** point: the disclosee accepts the rule section before content is revealed.

This codebase exposes the generic `exchange()` helper for `exn` envelopes; specific IPEX-route helpers are not provided — callers set the route string themselves.

## 7. Disclosure mechanisms

| Mechanism | Section | What's revealed | Implemented? |
| --- | --- | --- | :---: |
| **Partial** | Attribute (nested compaction) | Some nested attribute blocks revealed via SAID expansion; others stay compact | partial |
| **Selective** | Aggregate (`A`) | Individual blinded attribute blocks proven against the AGID | no (v2 only) |
| **Graduated** | Both | Staged: metadata → compact → partial → full, gated by `agree` in IPEX | no |
| **Chain-Link Confidentiality** | Rule | Disclosee must accept rule terms before content disclosure | shape only |

## 8. When to consult the upstream spec

- Implementing **selective-disclosure aggregate proofs** — exact AGID composition algorithm and JSON Schema layout matter.
- Adding **CESR-native ACDC serialization** (different from JSON, needs CESR genus codes).
- **Bound blinded attribute** semantics binding a blinded TEL event to a specific issuee key state.
- **Edge subschemas** with `oneOf` compositions for compact/expanded variants — subtle rules about `oneOf` ordering for SAID computation.
- Migrating to v2 TEL types (`rip` / `bup` / `upd`).

Direct links:
- [ACDC structure](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#acdc-structure)
- [Most compact form SAID](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#most-compact-form-said)
- [Edge section](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#edge-section)
- [Aggregate section](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#aggregate-section)
- [IPEX](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#issuance-and-presentation-exchange-ipex)
- [TEL registries](https://github.com/trustoverip/kswg-acdc-specification/blob/main/spec/spec-body.md#transaction-event-logs-tels-as-acdc-state-registries)
