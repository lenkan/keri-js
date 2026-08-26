# CESR — Curated Spec Reference

> Implementation-focused reference for the **Composable Event Streaming Representation** (CESR) specification.

**Upstream:** https://github.com/trustoverip/kswg-cesr-specification ([spec body](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md))

This codebase supports **both CESR v1 and v2**. KERI/ACDC events default to v1 (legacy version strings, `vcp`/`iss`/`rev` TEL types) but the parser, counter, and indexer accept either version. Pick the version per stream via the genus header (`-_AAABAA` = v1, `-_AAACAA` = v2).

## 1. Where things live

| Concern | File(s) |
| --- | --- |
| Code table constants (auto-generated) | `src/cesr/codes.ts` |
| Primitive (matter) encode/decode | `src/cesr/matter.ts` |
| Indexed signature encode/decode | `src/cesr/indexer.ts` |
| Count code framing (v1 + v2 registries) | `src/cesr/counter.ts`, `src/cesr/frame.ts` |
| Pad / lead-byte shifting | `src/cesr/shifting.ts` |
| Stream parser (cold-start) | `src/cesr/parse.ts` |
| Attachment groups | `src/cesr/attachments.ts`, `src/cesr/attachments-reader.ts`, `src/cesr/groups/` |
| Version string | `src/cesr/version-string.ts` |
| Protocol genus/version | `src/cesr/genus.ts` |
| Message framing | `src/cesr/message.ts` |

## 2. What CESR is

A self-describing, **dual-domain** encoding for cryptographic primitives and structured streams.

- **Text ('T') domain:** Base64URL chars. Inspectable, copy-pasteable.
- **Binary ('B') domain:** raw bytes. Compact.

Every primitive carries a stable type code as a prefix.

### Composability

Concatenating individually-encoded primitives equals encoding their concatenation as a whole — in both domains. Streams round-trip T ↔ B losslessly without re-padding. To make this work the encoding aligns to **24-bit boundaries** (LCM of 6-bit chars and 8-bit bytes): T-domain primitives are multiples of 4 chars, B-domain multiples of 3 bytes. Pads are pre-pended (zero bytes / extra code chars), never appended.

Pad size: `ps = (3 - (N mod 3)) mod 3`, `N` = raw length.

## 3. Code-table selectors

The first T-domain character (or first 3 bits — a **tritet** — in B-domain) selects the table:

| Selector | Table |
| --- | --- |
| `A`–`Z`, `a`–`z` | 1-char fixed-size codes |
| `0` | 2-char fixed-size codes |
| `1`, `2`, `3` | Large fixed-size — 4-char code, 0/1/2 lead bytes |
| `4`, `5`, `6` | Small variable-size — 4-char code, 2-char size |
| `7`, `8`, `9` | Large variable-size — 8-char code, 4-char size |
| `-` | Count code (group framing) |
| `_` | Op code (reserved) |

Min code length follows pad size: pad 0 → 4 chars, pad 1 → 1 char, pad 2 → 2 chars. Lead bytes pad raw values that aren't a multiple of 3 bytes.

## 4. Cold-start tritet table

| Tritet | Format | First T-domain char |
| :---: | --- | :---: |
| `0b000` | Annotated 'T' (whitespace) | (whitespace) |
| `0b001` | CESR 'T' Count Code | `-` |
| `0b010` | CESR 'T' Op Code | `_` |
| `0b011` | JSON map | `{` |
| `0b100` | MGPK FixMap | — |
| `0b101` | CBOR map (Major Type 5) | — |
| `0b110` | MGPK Map16 / Map32 | — |
| `0b111` | CESR 'B' Count or Op Code | — |

The actual parser (`src/cesr/parse.ts`) dispatches on the first T-domain character (`{`, `-`, `_`, …) rather than tritet bits, but the semantics are equivalent.

For JSON / CBOR / MGPK messages the `v` (version string) field carries protocol genus, version, and body length. For CESR groups, the count code declares the quadlet/triplet count.

## 5. Count codes

Count codes are non-primitive — they declare how many quadlets (T) / triplets (B) follow.

| Form | Format | Range |
| --- | --- | --- |
| Small | `-[A-Z,a-z]##` | 0–4,095 (1-char selector + 2-char count) |
| Large | `--[A-Z,a-z]#####` | 0–1,073,741,823 (1-char selector + 5-char count) |

Common groups for KERI/ACDC streams:

| Code | Group |
| --- | --- |
| `-A##` | Generic pipeline group |
| `-B##` | Message + attachments group |
| `--A#####` | Generic pipeline, large variant |
| `-_AAABAA` | Genus header — KERI/ACDC v1 |
| `-_AAACAA` | Genus header — KERI/ACDC v2 |

`Counter.v1` and `Counter.v2` (`src/cesr/counter.ts`) hold the per-version code tables. Parser version is selectable via `parse(input, { version: 1 | 2 })`; default is v1.

For attachment-specific count codes (controller signatures, witness receipts, seal source couples, pathed material, etc.) see `Counter.v1` / `Counter.v2` entries — they map directly onto the upstream Annex A tables.

## 6. Indexed codes (signatures)

Signatures attach with an **index** identifying which key in `k` they signed for, optionally an **ondex** (other index) for prior key state.

| Selector | Index chars | Ondex chars | Code chars | Format |
| :---: | :---: | :---: | :---: | --- |
| `A`–`Z`,`a`–`z` | 1 | 0 | 2 | `$#&&` |
| `0` | 1 | 1 | 4 | `0$##&&&&` |
| `2` | 2 | 2 | 6 | `2$####&&&&` |
| `3` | 3 | 3 | 6 | `3$######&&&&` |

Legend: `$` = type, `#` = index/ondex chars, `&` = value chars.

## 7. Stream parsing

```
loop:
  peek first char
  case '{'    → parse JSON message; read `v` for size; look for trailing -A/-B group
  case '-'    → parse count code; descend into group of `count` quadlets
  case '_'    → op code (reserved)
  case ws     → skip
  // CBOR / MGPK paths similar but via tritet on raw bytes
```

Group recursion is tritet-checked on each member, so groups can mix domains and serializations as long as composability holds.

## 8. When to consult the upstream spec

- Looking up a code not surfaced through `MatterTable` / `Counter` registries.
- Implementing a new primitive (cipher, encrypter, salt, …) not yet in `matter.ts`.
- Op codes (selector `_`) — reserved space, mostly unspecified.
- Pad-size / lead-byte edge cases — the spec has worked examples.

Direct links:
- [Composability and pad-size theory](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md#composability-and-domain-representations)
- [Master code table (Annex A)](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md#annex-a)
- [Cold-start parsing](https://github.com/trustoverip/kswg-cesr-specification/blob/main/spec/spec-body.md#cold-start-stream-parsing-problem)
