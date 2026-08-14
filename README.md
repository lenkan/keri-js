# KERI for JS

Playground KERI library for javascript. See test_interop for KERIpy compatibility tests. The library can create events, messages and credentials that can be verified by KERIpy. Currently, it does minimal verification.

## Packages

| Package | Description |
| --- | --- |
| [`cesr`](packages/cesr) | Composable Event Streaming Representation: encoding, decoding and stream parsing |
| [`keri`](packages/keri) | Key events, credentials, controller, witness and mailbox |

## Development

```sh
npm install
npm run build           # Build both packages
npm run test            # Unit tests
npm run lint            # Biome lint + import boundary check
npm run check           # TypeScript type-check

npm run test:consumer   # Public-surface tests through package names
npm run test:vector     # Cross-impl test vectors
npm run test:interop    # Interop tests (requires .venv with KERIpy)
```

`keri` resolves `cesr` through its built output, so the build runs before check and test. The
`pretest` and `precheck` hooks handle this; `tsc -b` keeps it incremental.

The verifier app lives in [`apps/verifier`](apps/verifier):

```sh
npm run dev:verifier
```
