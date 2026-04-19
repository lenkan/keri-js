import type { IncomingMessage, RequestListener } from "node:http";
import { Readable } from "node:stream";
import { type Logger, noopLogger } from "./logger.ts";

export interface ListenerOptions {
  logger?: Logger;
}

function toWebRequest(req: IncomingMessage): Request {
  const host = req.headers.host ?? "0.0.0.0";
  const protocol = req.headers["x-forwarded-proto"] ?? "http";
  const url = new URL(req.url ?? "/", `${protocol}://${host}`);

  const headers = new Headers();
  for (const [key, headerValue] of Object.entries(req.headers)) {
    if (headerValue !== undefined) {
      if (Array.isArray(headerValue)) {
        for (const value of headerValue) {
          headers.append(key, value);
        }
      } else {
        headers.set(key, headerValue);
      }
    }
  }

  let body: BodyInit | null = null;
  if (!["GET", "HEAD"].includes(req.method ?? "")) {
    body = Readable.toWeb(req) as ReadableStream<Uint8Array>;
  }

  return new Request(url, {
    method: req.method,
    headers,
    body,
    duplex: "half",
    // Cast required because DOM types omit `duplex`, but Node.js undici fetch requires it when body is a stream
  } as RequestInit & { duplex: "half" });
}

export function createListener(
  handler: (request: Request) => Promise<Response>,
  options: ListenerOptions = {},
): RequestListener {
  const log = options.logger ?? noopLogger;

  return async (req, res) => {
    const start = Date.now();
    const method = req.method ?? "GET";
    const url = req.url ?? "/";

    res.on("finish", () => {
      const durationMs = Date.now() - start;
      log.info(`${method} ${url} ${res.statusCode} ${durationMs}ms`, {
        method,
        url,
        status: res.statusCode,
        durationMs,
      });
    });

    try {
      const response = await handler(toWebRequest(req));
      res.writeHead(response.status, Object.fromEntries(response.headers.entries()));

      if (response.body) {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      }
      res.end();
    } catch (err) {
      log.error("handler threw", { method, url, error: err instanceof Error ? err.message : String(err) });
      res.statusCode = 500;
      res.end("Internal Server Error");
    }
  };
}
