# KERI for JS

Playground KERI library for javascript. See test_interop for KERIpy compatibility tests. The library can create events, messages and credentials that can be verified by KERIpy. Currently, it does minimal verification.

## Packages

| Package | Description |
| --- | --- |
| [`cesr`](packages/cesr) | Composable Event Streaming Representation: encoding, decoding and stream parsing |
| [`keri`](packages/keri) | Key events, credentials, controller, witness and mailbox |

## Development

This is a [pnpm](https://pnpm.io) workspace.

```sh
pnpm install
pnpm run build           # Build both packages
pnpm run test            # Unit tests
pnpm run lint            # Biome lint + import boundary check
pnpm run check           # TypeScript type-check

pnpm run test:consumer   # Public-surface tests through package names
pnpm run test:vector     # Cross-impl test vectors
pnpm run test:interop    # Interop tests (requires .venv with KERIpy)
```

`keri` resolves `cesr` through its built output, so the build runs before check and test. The
`pretest` and `precheck` hooks handle this; `tsc -b` keeps it incremental.

The verifier app lives in [`apps/verifier`](apps/verifier):

```sh
pnpm run dev:verifier
```
