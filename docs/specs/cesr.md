# CESR — Curated Spec Reference

> Curated reference for the **Composable Event Streaming Representation** (CESR) specification, written for AI assistants and human implementers working in this repo. Distilled from the upstream spec, with links back to the source for anything not covered here.

**Upstream:** https://github.com/trustoverip/kswg-cesr-specification
**Spec body:** [`spec/spec-body.md`](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md)

This file is the canonical place to look up CESR encoding rules, code tables, and parsing logic when working on `src/cesr/`. It is **not exhaustive** — for edge cases, always cross-check the upstream spec.

---

## 1. What CESR is

CESR is a self-describing, **dual-domain** encoding for cryptographic primitives and structured streams.

- **Text ('T') domain:** Base64URL-safe characters. Human-inspectable, copy-pasteable.
- **Binary ('B') domain:** raw bytes. Compact, suitable for transport and storage.
- A third **annotated text** domain exists for human-readable / debug streams.

Every primitive has a stable type code prefixed to the value. Type codes are themselves Base64URL characters in T-domain and bit-packed in B-domain.

### Composability (the defining property)

CESR is "composable": **concatenating individually-encoded primitives yields the same byte sequence as encoding their concatenation as a whole**. This holds in both domains, so streams round-trip losslessly between T and B without re-padding.

To make composability work:
- The encoding aligns to **24-bit boundaries** (LCM of 6-bit Base64 chars and 8-bit bytes).
- T-domain primitives are integer multiples of **4 Base64 chars**.
- B-domain primitives are integer multiples of **3 bytes**.
- Pads are pre-pended (as zero bytes / extra code chars) — never appended (no trailing `=`).

Pad size formula: `ps = (3 - (N mod 3)) mod 3`, where `N` is the raw binary length.

Implementation: `src/cesr/matter.ts`, `src/cesr/shifting.ts`.

---

## 2. Code tables and selectors

The first character of a T-domain code (or first 3 bits — a **tritet** — in B-domain) selects the table that decodes the rest.

### Selector assignments

| Selector char | Table |
| --- | --- |
| `A`–`Z`, `a`–`z` | 1-char fixed-size codes (52 types, pad size 1) |
| `0` | 2-char fixed-size codes (64 types, pad size 2) |
| `1`, `2`, `3` | Large fixed-size codes — 4-char code, 0/1/2 lead bytes |
| `4`, `5`, `6` | Small variable-size codes — 4-char code, 2-char size, 0/1/2 lead bytes |
| `7`, `8`, `9` | Large variable-size codes — 8-char code, 4-char size, 0/1/2 lead bytes |
| `-` | Count code (group framing) |
| `_` | Op code (reserved) |

Implementation: `src/cesr/codes.ts`.

### Parsing pattern

1. Read the **stable** (hardened) portion using the first character.
2. Use the parse-size table to learn how many code chars, size chars, and value chars/bytes follow.
3. For variable-size codes, decode the size field to get the value length.
4. Consume value; emit primitive; resume.

Implementation: `src/cesr/parse.ts`.

---

## 3. Cold-start parsing — top-level tritet table

The first 3 bits of a stream tell a parser what serialization is starting. This is how a parser cold-starts or re-syncs after a buffer flush.

| Tritet | Format | First T-domain char |
| :---: | --- | :---: |
| `0b000` | Annotated 'T' domain | (whitespace) |
| `0b001` | CESR 'T' Count Code | `-` |
| `0b010` | CESR 'T' Op Code | `_` |
| `0b011` | JSON map | `{` |
| `0b100` | MGPK FixMap | — |
| `0b101` | CBOR map (Major Type 5) | — |
| `0b110` | MGPK Map16 / Map32 | — |
| `0b111` | CESR 'B' domain Count or Op Code | — |

Once the stream type is known, the parser:
- For JSON / CBOR / MGPK: parse the message body, including the **version string** field `v` to identify the protocol genus, version, and total body length.
- For CESR Count Codes: read the count to learn the group's quadlet/triplet size, then descend into the group.

Implementation: `src/cesr/parse.ts`, `src/cesr/version-string.ts`, `src/cesr/genus.ts`.

---

## 4. Count codes (group framing)

Count codes are **non-primitive** — they don't carry a value, they declare how many quadlets (4-char T-domain units) or triplets (3-byte B-domain units) follow as a group.

### Small Count Code table

| Code | Meaning |
| --- | --- |
| `-[A-Z,a-z]##` | Count code with 1-char type selector and 2-char Base64 count (0–4,095). Total length 4 chars. |

### Large Count Code table

| Code | Meaning |
| --- | --- |
| `--[A-Z,a-z]#####` | 1-char type with 5-char Base64 count (0–1,073,741,823). Total length 8 chars. |

### Common count codes (KERI/ACDC genus `-_AAACAA`)

| Code | Group |
| --- | --- |
| `-A##` | Generic pipeline group |
| `-B##` | Message + attachments group |
| `--A#####` | Generic pipeline group, large variant |
| `-_AAABAA` | Protocol genus/version: KERI/ACDC v1.00 |
| `-_AAACAA` | Protocol genus/version: KERI/ACDC v2.00 |

Many more attachment-specific count codes exist (controller signatures, witness receipts, seal source couples, etc.) — see Annex A of the upstream spec for the full master code table.

Implementation: `src/cesr/counter.ts`, `src/cesr/frame.ts`, `src/cesr/groups/`.

---

## 5. Indexed codes (signatures)

Signatures attach to events with an **index** identifying which key in `k` produced them, and optionally an **ondex** (other index) for prior key state.

| Selector | Type | Index | Ondex | Code size | Lead | Pad | Format |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | --- |
| `A`–`Z`,`a`–`z` | 1 | 1 | 0 | 2 | 0 | 2 | `$#&&` |
| `0` | 1 | 1 | 1 | 4 | 0 | 0 | `0$##&&&&` |
| `2` | 1 | 2 | 2 | 6 | 0 | 2 | `2$####&&&&` |
| `3` | 1 | 3 | 3 | 6 | 0 | 0 | `3$######&&&&` |

Legend: `$` = type, `#` = index/ondex chars, `&` = value chars.

Implementation: `src/cesr/indexer.ts`.

---

## 6. Text-code-size rules

The minimum code length is determined by the pad size of the underlying raw value:

| Pad size | Min code chars |
| :---: | :---: |
| 0 | 4 |
| 1 | 1 |
| 2 | 2 |

This rule keeps the value bits naturally aligned in both domains: a code of pad-correct length leaves the value portion byte-aligned in B-domain and char-aligned in T-domain.

For raw values that aren't a multiple of 3 bytes, **lead bytes** (zero bytes prepended to the raw) take up the slack so the code+value composes into a 24-bit-aligned unit. Tables for "0 / 1 / 2 lead bytes" exist for each fixed/variable size class.

---

## 7. Stream parsing algorithm

```
loop:
  peek first tritet of stream
  switch tritet:
    case CESR-T Count or Op Code (`-` / `_`):
      parse count code → get group quadlet count
      recurse into group; consume `count` quadlets
    case CESR-B Count or Op Code:
      same but in binary domain
    case JSON / CBOR / MGPK:
      parse version string field `v` → get protocol genus, version, body length
      consume body
      look for following attachment group (`-A##` / `-B##`)
    case annotated text:
      skip whitespace, retry
```

Each group recursion is itself a tritet check on its first member, so a nested group can mix domains and serializations as long as composability rules hold.

Implementation: `src/cesr/parse.ts`, `src/cesr/attachments.ts`, `src/cesr/attachments-reader.ts`, `src/cesr/message.ts`.

---

## 8. Where things live in this repo

| Concern | File(s) |
| --- | --- |
| Code table constants | `src/cesr/codes.ts` |
| Primitive (matter) encode/decode | `src/cesr/matter.ts` |
| Indexed signature encode/decode | `src/cesr/indexer.ts` |
| Count code framing | `src/cesr/counter.ts`, `src/cesr/frame.ts` |
| Pad / lead-byte shifting | `src/cesr/shifting.ts` |
| Stream parser | `src/cesr/parse.ts` |
| Attachment groups | `src/cesr/attachments.ts`, `src/cesr/groups/` |
| Version string | `src/cesr/version-string.ts` |
| Protocol genus/version | `src/cesr/genus.ts` |
| Message framing | `src/cesr/message.ts` |

---

## 9. When to consult the upstream spec

Use the upstream spec directly when:

- Looking up an exact code in the **master code table** (Annex A) — full table is large and not reproduced here.
- Implementing a **new primitive type** (cipher, encrypter, salt, etc.) not yet handled in `matter.ts`.
- Reasoning about **op codes** (selector `_`) — reserved space, mostly unspecified.
- Cross-checking **edge cases in pad-size / lead-byte arithmetic** — the spec has worked examples.

Direct links:
- Composability and pad-size theory: [§ "Composability and Domain Representations"](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md#composability-and-domain-representations)
- Master code table: [§ "Annex A → KERI/ACDC Protocol Stack Tables"](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md#annex-a)
- Stream parsing rules: [§ "Cold start Stream parsing problem"](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md#cold-start-stream-parsing-problem)
