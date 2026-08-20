# @keri-js/verifier

The ACDC verifier: a React app that verifies credentials in the browser, and the
Cloudflare Worker that serves it, publishes the verifier's OOBI and receives
IPEX presentations.

Verification runs entirely in the page, on `keri`. The worker never inspects a
credential — it parks the presented stream in KV until the browser collects it.

| Route | |
| --- | --- |
| `GET /` | the app |
| `POST`/`PUT /` | receives a presentation (where KERIpy's `sendDirect` posts) |
| `GET /oobi` | the verifier's key event log as CESR |
| `POST /api/sessions` | mints a session token |
| `GET /api/sessions/:token` | reads back a delivered presentation |

Everything outside `/oobi` and `/api` is served from the assets binding, falling
back to the app shell for paths without a file extension.

## Run it locally

```sh
pnpm run dev:verifier
```

One vite process serves the app and runs the worker in workerd, with KV and the
assets binding simulated locally. No Cloudflare account needed.

## Bindings and variables

| Name | |
| --- | --- |
| `ASSETS` | assets binding, serving the client build |
| `SESSIONS` | KV namespace holding presentations, keyed by session token |
| `VERIFIER_URL` | public base URL, baked into the OOBI; defaults to the request origin |
| `VERIFIER_SEED` | 32-byte base64 seed for the verifier's key |

Without `VERIFIER_SEED` the identity is ephemeral and every isolate invents its
own, so the published OOBI goes stale. Set it as a secret — it is the verifier's
signing key:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | \
  pnpm --filter @keri-js/verifier exec wrangler secret put VERIFIER_SEED
```

## Deployment

Pushing to `main` deploys, through a Cloudflare Workers Build connected to this
repository. The build settings live in the Cloudflare dashboard, under the
`keri-verifier` worker:

| Setting | |
| --- | --- |
| Root directory | `/` (the repository root) |
| Build command | `pnpm install --frozen-lockfile && pnpm run build` |
| Deploy command | `pnpm run deploy:verifier` |
| Build variables | `PNPM_VERSION=11.21.0`, `SKIP_DEPENDENCY_INSTALL=1` |

The build command builds the workspace packages only; `deploy:verifier` runs
`vite build` itself, which emits the client bundle, the worker, and the
`wrangler.json` that `wrangler deploy` then reads.

`SKIP_DEPENDENCY_INSTALL` is what lets the build command install with
`--frozen-lockfile`, which the image's own install does not. `PNPM_VERSION` has
to match the `packageManager` pin in the root manifest, which the image's older
pnpm would otherwise refuse. The Node version comes from `.nvmrc` at the
repository root.

To deploy by hand:

```sh
pnpm run deploy:verifier
```

The KV namespace already exists. To recreate it elsewhere:

```sh
pnpm --filter @keri-js/verifier exec wrangler kv namespace create SESSIONS
# put the returned id into wrangler.jsonc
```
