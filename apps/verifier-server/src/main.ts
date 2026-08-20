/** biome-ignore-all lint/suspicious/noConsole: worker entrypoint */
import { createVerifierRouter, type SessionStore, Verifier } from "@keri-js/infra/verifier";
import { decodeBase64Url } from "cesr/encoding";

interface Env {
  ASSETS: Fetcher;
  SESSIONS: KVNamespace;
  VERIFIER_URL?: string;
  VERIFIER_SEED?: string;
}

// The protocol owns these: `/` takes presentations from KERIpy's sendDirect and
// `/oobi` publishes the identity, so neither can be shadowed by the app shell.
const RESERVED = /^\/(oobi|api)(\/|$)/;

// Built once per isolate. The verifier derives a key and assembles its own key
// event log, which is wasted work on every request.
let router: ((request: Request) => Promise<Response>) | undefined;

function sessions(kv: KVNamespace): SessionStore {
  return {
    get: (token) => kv.get(token),
    // Workers KV rejects a TTL under 60s. The router asks for ten minutes, so
    // this only guards a future caller from shortening it into a silent error.
    put: (token, cesr, ttlMs) => kv.put(token, cesr, { expirationTtl: Math.max(60, Math.round(ttlMs / 1000)) }),
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

function build(env: Env, request: Request) {
  // The AID has to survive redeploys, or every published OOBI goes stale.
  const seed = env.VERIFIER_SEED;

  if (!seed) {
    console.warn("VERIFIER_SEED is not set, using an ephemeral identity for this isolate only");
  }

  const url = env.VERIFIER_URL ?? new URL(request.url).origin;
  const verifier = new Verifier({ privateKey: seed ? decodeSeed(seed) : undefined, url });

  return createVerifierRouter(verifier, sessions(env.SESSIONS), { logger: console });
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
    router ??= build(env, request);

    const { pathname } = new URL(request.url);

    if ((request.method === "GET" || request.method === "HEAD") && !RESERVED.test(pathname)) {
      const response = await asset(request, env);

      if (response) {
        return response;
      }
    }

    return router(request);
  },
} satisfies ExportedHandler<Env>;
