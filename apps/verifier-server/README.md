# @keri-js/verifier-server

Serves the ACDC verifier: the API that mints presentation sessions and receives
IPEX grants, the verifier's OOBI, and the built `@keri-js/verifier` app.

| Route | |
| --- | --- |
| `GET /` | the app, or `{"status":"OK"}` when no static directory is present |
| `POST`/`PUT /` | receives a presentation (where KERIpy's `sendDirect` posts) |
| `GET /oobi` | the verifier's key event log as CESR |
| `POST /api/sessions` | mints a session token |
| `GET /api/sessions/:token` | reads back a delivered presentation |

## Run it locally

```sh
pnpm run dev:verifier    # the app on :5173 proxying to this server on :3002
```

The app and the server run as two processes in dev; vite proxies `/api` and
`/oobi` so the page is same-origin. To run the deployed shape instead — one
origin serving both:

```sh
pnpm run build:apps
VERIFIER_STATIC_DIR=../verifier/dist pnpm --filter @keri-js/verifier-server run dev
```

## Environment

| Variable | |
| --- | --- |
| `PORT` | defaults to `3002` |
| `VERIFIER_URL` | public base URL, baked into the OOBI |
| `VERIFIER_SEED` | 32-byte base64 seed for the verifier's key |
| `VERIFIER_STATIC_DIR` | built app to serve; defaults to `./static`, and serving is skipped when it is absent |

Without `VERIFIER_SEED` the identity is ephemeral, so every restart invalidates
the published OOBI. Store it as a secret — it is the verifier's signing key.

## Deployment

Deployed by Deno Deploy's Git integration, which builds from the repository on
push. There is no deploy workflow in this repo. Settings:

| Setting | Value |
| --- | --- |
| App directory | repository root |
| Install command | `pnpm install` |
| Build command | `pnpm run build:apps` |
| Entrypoint | `apps/verifier-server/src/main.ts` |
| Runtime mode | dynamic |

Set `VERIFIER_URL`, `VERIFIER_SEED` and `VERIFIER_STATIC_DIR=apps/verifier/dist`
on the application, and assign a Deno KV database — sessions are stored in it.
