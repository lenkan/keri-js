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
pnpm run package
cd dist && deno run --allow-net --allow-env --allow-read --unstable-kv server.js
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

Deployed to Deno Deploy by uploading a pre-built bundle. From a checkout:

```sh
pnpm run package
deno deploy --prod dist
```

`pnpm run package` builds the packages and both apps, then assembles `dist/`
as `server.js` — the server with every dependency inlined — and `static/`, the
built app. `deno.json` records the org and application, so neither needs a flag.

| Setting | Value |
| --- | --- |
| Source | local |
| Install command | none |
| Build command | none |
| Entrypoint | `server.js` |
| Runtime mode | dynamic |

The upload carries no `package.json`, so an install command configured on the
application fails the build before it starts.

Set `VERIFIER_URL` and `VERIFIER_SEED` on the application, and assign a Deno KV
database — sessions are stored in it. `VERIFIER_STATIC_DIR` is not needed and
must not be set: the server runs from the upload root, where the default
`./static` already resolves.
