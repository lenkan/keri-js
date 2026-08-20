/** biome-ignore-all lint/suspicious/noConsole: worker entrypoint */
import { createVerifierRouter, type KeyEventStore, type SessionStore, Verifier } from "@keri-js/infra/verifier";
import { decodeBase64Url } from "cesr/encoding";

// ASSETS and SESSIONS come from worker-configuration.d.ts, which `wrangler types`
// generates from the bindings. Secrets are not in the config, so they are only
// known here.
declare global {
  interface Env {
    VERIFIER_URL?: string;
    VERIFIER_SEED?: string;
  }
}

// The protocol owns these: `/` takes presentations from KERIpy's sendDirect and
// `/oobi` publishes the identity, so neither can be shadowed by the app shell.
const RESERVED = /^\/(oobi|api)(\/|$)/;

// Deriving the key and assembling the key event log is the most expensive thing
// this worker does, and isolates are reused, so it is memoised. The cache is
// keyed by the url it was built for: nothing request-scoped may outlive the
// request that produced it, and the url is request-derived when VERIFIER_URL is
// unset. Setting VERIFIER_URL makes this depend on bindings alone.
let cached: { url: string; router: Promise<(request: Request) => Promise<Response>> } | undefined;

function sessions(kv: KVNamespace): SessionStore {
  return {
    get: (token) => kv.get(token),
    // Workers KV rejects a TTL under 60s. The router asks for ten minutes, so
    // this only guards a future caller from shortening it into a silent error.
    put: (token, cesr, ttlMs) => kv.put(token, cesr, { expirationTtl: Math.max(60, Math.round(ttlMs / 1000)) }),
  };
}

// Key events are first-seen evidence, so they never expire — unlike sessions.
// Sequence numbers are stored as padded hex so the keys sort, should a future
// feature need to list them.
function keyEvents(kv: KVNamespace): KeyEventStore {
  const eventKey = (aid: string, sn: bigint) => `kel:${aid}:${sn.toString(16).padStart(16, "0")}`;

  return {
    getEvent: (aid, sn) => kv.get(eventKey(aid, sn), "json"),
    putEvent: (aid, sn, event) => kv.put(eventKey(aid, sn), JSON.stringify(event)),
    getHead: (aid) => kv.get(`kel:${aid}`, "json"),
    putHead: (aid, head) => kv.put(`kel:${aid}`, JSON.stringify(head)),
  };
}

function decodeSeed(value: string): Uint8Array {
  // `openssl rand -base64 32` is the obvious way to mint this, and it emits
  // padded standard base64. decodeBase64Url consumes the padding as data rather
  // than rejecting it, so the seed silently arrives 33 bytes long.
  const normalized = value.trim().replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  const bytes = decodeBase64Url(normalized);

  if (bytes.length !== 32) {
    throw new Error(`VERIFIER_SEED must decode to 32 bytes, got ${bytes.length}`);
  }

  return bytes;
}

function route(env: Env, request: Request): Promise<(request: Request) => Promise<Response>> {
  const url = env.VERIFIER_URL ?? new URL(request.url).origin;

  if (cached?.url === url) {
    return cached.router;
  }

  // The AID has to survive redeploys, or every published OOBI goes stale.
  const seed = env.VERIFIER_SEED;

  if (!seed) {
    console.warn("VERIFIER_SEED is not set, using an ephemeral identity for this isolate only");
  }

  // The promise is what gets cached, so requests arriving during a cold start
  // share one key derivation instead of each racing to build their own.
  const router = Verifier.create({ privateKey: seed ? decodeSeed(seed) : undefined, url }).then((verifier) =>
    createVerifierRouter(verifier, sessions(env.SESSIONS), keyEvents(env.SESSIONS), { logger: console }),
  );

  cached = { url, router };

  return router;
}

/** The built app, or null when the request is not the asset server's to answer. */
async function asset(request: Request, env: Env): Promise<Response | null> {
  const response = await env.ASSETS.fetch(request);

  if (response.status !== 404) {
    return response;
  }

  // A path with an extension is a missing asset, not a route: answering for a
  // script with the app shell would hide the 404 behind a page of HTML.
  const { pathname, origin } = new URL(request.url);

  if (/\.[^./]+$/.test(pathname)) {
    return null;
  }

  const shell = await env.ASSETS.fetch(new Request(`${origin}/index.html`, request));

  return shell.status === 404 ? null : shell;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);

    if ((request.method === "GET" || request.method === "HEAD") && !RESERVED.test(pathname)) {
      const response = await asset(request, env);

      if (response) {
        return response;
      }
    }

    const router = await route(env, request);

    return router(request);
  },
} satisfies ExportedHandler<Env>;
