import { KeyEventLog } from "keri";

/** The KEL could not be retrieved: bad URL, network failure, or an error status. */
export class KelFetchError extends Error {}

/** The response arrived but did not parse and verify as a key event log. */
export class KelParseError extends Error {}

export interface FetchKelOptions {
  fetch?: typeof globalThis.fetch;
  maxBytes?: number;
}

const DEFAULT_MAX_BYTES = 256 * 1024;

async function* cap(stream: AsyncIterable<Uint8Array>, maxBytes: number): AsyncIterable<Uint8Array> {
  let total = 0;

  for await (const chunk of stream) {
    total += chunk.length;
    if (total > maxBytes) {
      throw new KelFetchError(`Response exceeds ${maxBytes} bytes`);
    }
    yield chunk;
  }
}

/**
 * Fetch a KEL from an OOBI URL and replay it into a verified {@link KeyEventLog},
 * without touching storage. Receipts and replies in the stream are ignored, and
 * partially witnessed KELs are accepted — this proves key control, not witness
 * liveness.
 *
 * Only http(s) URLs are accepted; on Node the URL can still name a private
 * address, so callers taking untrusted URLs should consider where they run.
 */
export async function fetchKel(url: string | URL, options: FetchKelOptions = {}): Promise<KeyEventLog> {
  let target: URL;
  try {
    target = new URL(url);
  } catch (cause) {
    throw new KelFetchError(`Invalid URL: ${url}`, { cause });
  }

  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new KelFetchError(`Invalid protocol: ${target}`);
  }

  const doFetch = options.fetch ?? globalThis.fetch;

  let response: Response;
  try {
    response = await doFetch(target);
  } catch (cause) {
    throw new KelFetchError(`Failed to fetch ${target}: ${cause instanceof Error ? cause.message : String(cause)}`, {
      cause,
    });
  }

  if (!response.ok || !response.body) {
    throw new KelFetchError(`Failed to fetch ${target}: ${response.status} ${response.statusText}`);
  }

  try {
    return await KeyEventLog.parse(cap(response.body, options.maxBytes ?? DEFAULT_MAX_BYTES), {
      allowPartiallyWitnessed: true,
    });
  } catch (cause) {
    if (cause instanceof KelFetchError) {
      throw cause;
    }

    throw new KelParseError(
      `Response from ${target} is not a valid key event log: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
}
