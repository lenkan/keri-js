# @keri-js/verifier-server

Serves the ACDC verifier as a Cloudflare Worker: the API that mints presentation
sessions and receives IPEX grants, the verifier's OOBI, and the built
`@keri-js/verifier` app.

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
pnpm run dev:verifier    # the app on :5173 proxying to the worker on :3002
```

The app and the worker run as two processes in dev; vite proxies `/api` and
`/oobi` so the page is same-origin. To run the deployed shape instead — the
worker serving both — build the app first, since the assets binding reads it
from disk:

```sh
pnpm run build:apps
pnpm --filter @keri-js/verifier-server run dev
```

`wrangler dev` simulates KV and the assets binding locally; no account needed.

## Bindings and variables

| Name | |
| --- | --- |
| `ASSETS` | assets binding, serving `apps/verifier/dist` |
| `SESSIONS` | KV namespace holding presentations, keyed by session token |
| `VERIFIER_URL` | public base URL, baked into the OOBI; defaults to the request origin |
| `VERIFIER_SEED` | 32-byte base64 seed for the verifier's key |

Without `VERIFIER_SEED` the identity is ephemeral and every isolate invents its
own, so the published OOBI goes stale. Set it as a secret — it is the verifier's
signing key:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | \
  pnpm --filter @keri-js/verifier-server exec wrangler secret put VERIFIER_SEED
```

## Deployment

Pushing to `main` deploys, through a Cloudflare Workers Build connected to this
repository. The build settings live in the Cloudflare dashboard, under the
`keri-verifier` worker:

| Setting | |
| --- | --- |
| Root directory | `apps/verifier-server` |
| Build command | `pnpm install --frozen-lockfile && pnpm -w run build:apps` |
| Deploy command | `pnpm exec wrangler deploy` |
| Build variables | `NODE_VERSION=24`, `PNPM_VERSION=11.21.0`, `SKIP_DEPENDENCY_INSTALL=1` |

`SKIP_DEPENDENCY_INSTALL` turns off the build image's own install so the build
command can run `pnpm install --frozen-lockfile`, which the automatic one does
not. The image's default pnpm is older than the `packageManager` pin in the root
manifest, hence `PNPM_VERSION`.

Nothing gates the build on CI, so a red `main` still ships. The tests run on the
pull request instead.

To deploy by hand:

```sh
pnpm run build:apps
pnpm --filter @keri-js/verifier-server run deploy
```

`build:apps` builds the packages and the app; `wrangler deploy` bundles the
worker and uploads it with the assets directory.

The KV namespace already exists. To recreate it elsewhere:

```sh
pnpm --filter @keri-js/verifier-server exec wrangler kv namespace create SESSIONS
# put the returned id into wrangler.jsonc
```
