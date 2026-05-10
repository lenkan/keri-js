# Curated spec references

Implementation-focused summaries of the protocol specs that this codebase implements. Each file is hand-curated from the upstream spec and links back for anything not covered.

| Spec | Doc | Upstream |
| --- | --- | --- |
| CESR | [`cesr.md`](./cesr.md) | [trustoverip/kswg-cesr-specification](https://github.com/trustoverip/kswg-cesr-specification) |
| KERI | [`keri.md`](./keri.md) | [trustoverip/kswg-keri-specification](https://github.com/trustoverip/kswg-keri-specification) |
| ACDC | _not yet curated_ | [trustoverip/kswg-acdc-specification](https://github.com/trustoverip/kswg-acdc-specification) |

These are the canonical in-repo references for protocol-level questions. They cover:

- Field labels, event types, and message structure
- Encoding rules, code tables, and parsing logic
- Cross-references to where each concept is implemented in `src/`

For witness-agreement specifics, see [`../kawa.md`](../kawa.md). The older [`../KERI.md`](../KERI.md) is a high-level overview kept for legacy reference; prefer the curated docs here.
