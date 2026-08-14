# Curated spec references

Implementation-focused summaries of the protocol specs that this codebase implements. Each file is hand-curated from the upstream spec and links back for anything not covered.

| Spec | Doc | Upstream | Implementation status |
| --- | --- | --- | --- |
| CESR | [`cesr.md`](./cesr.md) | [trustoverip/kswg-cesr-specification](https://github.com/trustoverip/kswg-cesr-specification) | v1 + v2 |
| KERI | [`keri.md`](./keri.md) | [trustoverip/kswg-keri-specification](https://github.com/trustoverip/kswg-keri-specification) | v1 |
| ACDC | [`acdc.md`](./acdc.md) | [trustoverip/kswg-acdc-specification](https://github.com/trustoverip/kswg-acdc-specification) | v1 |

These are the canonical in-repo references for protocol-level questions. They cover:

- Field labels, event types, and message structure
- Encoding rules, code tables, and parsing logic
- Cross-references to where each concept is implemented in `packages/*/src`

For witness-agreement specifics, see [`../kawa.md`](../kawa.md).
