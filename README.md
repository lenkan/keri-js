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
pnpm run test:e2e        # Verifier browser tests (requires .venv with KERIpy)
```

`test:e2e` drives the verifier app in a browser and does not start it — run `pnpm run dev:verifier`
first, or point `E2E_BASE_URL` at another host. Install the browser once with
`pnpm exec playwright install chromium`.

`keri` resolves `cesr` through its built output, so the build runs before check and test. The
`pretest` and `precheck` hooks handle this; `tsc -b` keeps it incremental.

## Apps

The verifier app lives in [`apps/verifier`](apps/verifier):

```sh
pnpm run dev:verifier
```

[`apps/witness`](apps/witness) and [`apps/mailbox`](apps/mailbox) are local servers for development
and manual testing. They store key events in memory, so nothing survives a restart.

```sh
pnpm run dev:witness
PORT=3001 pnpm run dev:mailbox
```

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Port to listen on |
| `PASSPHRASE` | `password` | Passphrase the key is derived from; an unchanged passphrase and salt mean the same AID across restarts |
| `SALT` | `salt` | Salt for the key derivation |
| `WITNESS_URL` / `MAILBOX_URL` | `http://localhost:$PORT` | URL the server publishes in its OOBI |
