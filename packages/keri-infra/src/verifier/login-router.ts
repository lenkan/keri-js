import type { Message } from "cesr";
import type { ExchangeEventBody } from "keri";
import { KeyEventLog, RoutedEvent } from "keri";
import { fetchKel, KelFetchError, KelParseError } from "../http/main.ts";
import type { KeriLogger } from "../logging/main.ts";
import { generateWords, identityOf, type KeyEventStore, type LoginRecord, recordKeyEvents, wordsKey } from "./login.ts";
import type { SessionStore } from "./verifier.ts";

// A KEL submission can carry witness receipts, so it gets more headroom than a
// presentation; only the derived state is stored, so KV value caps don't bind.
const MAX_KEL_BYTES = 256 * 1024;

export interface LoginHandlerOptions {
  sessions: SessionStore;
  keyEvents: KeyEventStore;
  log: KeriLogger;
  sessionTtlMs: number;
  fetch?: typeof globalThis.fetch;
}

export interface LoginHandlers {
  handleKelSubmission(request: Request, token: string): Promise<Response>;
  handleOobiSubmission(request: Request, token: string): Promise<Response>;
  handleLoginRead(token: string): Promise<Response>;
  handleChallengeResponse(message: Message<ExchangeEventBody>): Promise<Response>;
}

/**
 * The login half of the verifier's surface: KEL intake (pushed or pulled),
 * challenge issuance, status reads, and one-shot response verification. Mounted
 * by the verifier router, which owns routing, CORS and token minting.
 */
export function createLoginHandlers(options: LoginHandlerOptions): LoginHandlers {
  const { sessions, keyEvents, log, sessionTtlMs } = options;

  async function readLogin(token: string): Promise<LoginRecord | null> {
    const value = await sessions.get(`login:${token}`);
    return value ? (JSON.parse(value) as LoginRecord) : null;
  }

  async function writeLogin(token: string, record: LoginRecord): Promise<void> {
    await sessions.put(`login:${token}`, JSON.stringify(record), sessionTtlMs);
  }

  /** Both KEL intake paths converge here once a verified log exists. */
  async function issueChallenge(token: string, kel: KeyEventLog): Promise<Response> {
    const recorded = await recordKeyEvents(keyEvents, kel);
    if (!recorded.ok) {
      log.warn("rejecting conflicting key event history", { aid: recorded.aid, sn: recorded.sn.toString() });
      return Response.json(
        { error: `Conflicting key event history for ${recorded.aid} at sequence number ${recorded.sn}` },
        { status: 409 },
      );
    }

    const aid = kel.state.identifier;
    const words = generateWords();

    await Promise.all([
      writeLogin(token, { phase: "challenged", aid, state: kel.state, words }),
      sessions.put(`words:${wordsKey(words)}`, token, sessionTtlMs),
    ]);
    log.debug("issued challenge", { aid });

    return Response.json({ aid, words });
  }

  return {
    async handleKelSubmission(request: Request, token: string): Promise<Response> {
      const declared = Number(request.headers.get("Content-Length"));
      if (declared > MAX_KEL_BYTES) {
        return Response.json({ error: "Key event log too large" }, { status: 413 });
      }

      const bytes = new Uint8Array(await request.arrayBuffer());
      if (bytes.length > MAX_KEL_BYTES) {
        return Response.json({ error: "Key event log too large" }, { status: 413 });
      }

      let kel: KeyEventLog;
      try {
        kel = await KeyEventLog.parse(bytes, { allowPartiallyWitnessed: true });
      } catch (cause) {
        log.warn("could not parse submitted KEL", { error: cause instanceof Error ? cause.message : String(cause) });
        return Response.json({ error: "The body is not a valid key event log" }, { status: 400 });
      }

      return issueChallenge(token, kel);
    },

    async handleOobiSubmission(request: Request, token: string): Promise<Response> {
      const body = (await request.json().catch(() => ({}))) as { url?: unknown };
      const url = body.url;

      if (typeof url !== "string" || !/^https?:\/\//.test(url)) {
        return Response.json({ error: "Pass a JSON body with an http(s) `url`" }, { status: 400 });
      }

      let kel: KeyEventLog;
      try {
        kel = await fetchKel(url, { fetch: options.fetch, maxBytes: MAX_KEL_BYTES });
      } catch (cause) {
        const error = cause instanceof Error ? cause.message : String(cause);
        log.warn("could not resolve OOBI", { error });

        if (cause instanceof KelFetchError) {
          return Response.json({ error: `Could not fetch the OOBI: ${error}` }, { status: 502 });
        }
        if (cause instanceof KelParseError) {
          return Response.json({ error: "The OOBI did not resolve to a valid key event log" }, { status: 400 });
        }
        throw cause;
      }

      return issueChallenge(token, kel);
    },

    async handleLoginRead(token: string): Promise<Response> {
      const record = await readLogin(token);

      if (!record) {
        return new Response(null, { status: 204 });
      }

      if (record.phase === "authenticated") {
        return Response.json({ phase: record.phase, identity: identityOf(record) });
      }

      return Response.json({ phase: record.phase, aid: record.aid, words: record.words, error: record.error });
    },

    async handleChallengeResponse(message: Message<ExchangeEventBody>): Promise<Response> {
      const words = message.body.a?.words;
      if (!Array.isArray(words) || words.length === 0 || !words.every((word) => typeof word === "string")) {
        return Response.json({ error: "The challenge response carries no words" }, { status: 400 });
      }

      // The response has no token field, so the words are the correlator. The
      // token lookup can trail a just-written mapping on another KV colo — hence
      // the retry hint.
      const token = await sessions.get(`words:${wordsKey(words)}`);
      const record = token ? await readLogin(token) : null;

      if (!token || !record) {
        log.warn("challenge response for unknown words");
        return Response.json({ error: "Unknown or expired challenge — retry in a moment" }, { status: 404 });
      }

      if (record.phase === "authenticated") {
        log.warn("replayed challenge response", { aid: record.aid });
        return Response.json({ error: "Challenge already used" }, { status: 410 });
      }

      if (record.words.join(" ") !== words.join(" ")) {
        // A stale words mapping from before a re-submission re-challenged.
        return Response.json({ error: "Unknown or expired challenge — retry in a moment" }, { status: 404 });
      }

      if (message.body.i !== record.aid || message.body.a.i !== record.aid) {
        const error = "The response is signed by a different AID than the submitted key event log";
        await writeLogin(token, { ...record, error });
        return Response.json({ error }, { status: 400 });
      }

      const verdict = RoutedEvent.verifyExchange(message, record.state);
      if (!verdict.ok) {
        log.warn("rejecting challenge response", { aid: record.aid, kind: verdict.kind, error: verdict.error });
        const stale = verdict.kind === "stale-establishment";
        const error = stale
          ? "Key event log out of date — re-run the export step after rotating, then respond again"
          : `Invalid challenge response: ${verdict.error}`;
        await writeLogin(token, { ...record, error });
        return Response.json({ error }, { status: stale ? 409 : 400 });
      }

      await writeLogin(token, {
        phase: "authenticated",
        aid: record.aid,
        state: record.state,
        authenticatedAt: new Date().toISOString(),
      });
      log.debug("authenticated", { aid: record.aid });

      return new Response(null, { status: 204 });
    },
  };
}
