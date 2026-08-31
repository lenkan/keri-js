import type { IncomingMessage, RequestListener } from "node:http";
import { Readable } from "node:stream";

/**
 * Node's `http` server in terms of the Web `Request`/`Response` a `Witness`
 * speaks. Lives in `test_utils` rather than in the package: it is `node:http`
 * glue, and `src/` may not import a `node:` builtin.
 */
function toWebRequest(req: IncomingMessage): Request {
  const host = req.headers.host ?? "0.0.0.0";
  const protocol = req.headers["x-forwarded-proto"] ?? "http";
  const url = new URL(req.url ?? "/", `${protocol}://${host}`);

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) {
      continue;
    }
    for (const entry of Array.isArray(value) ? value : [value]) {
      headers.append(key, entry);
    }
  }

  const body = ["GET", "HEAD"].includes(req.method ?? "") ? null : (Readable.toWeb(req) as ReadableStream<Uint8Array>);

  return new Request(url, {
    method: req.method,
    headers,
    body,
    // The DOM types omit `duplex`, but undici requires it when the body streams.
    duplex: "half",
  } as RequestInit & { duplex: "half" });
}

export function createListener(handler: (request: Request) => Promise<Response>): RequestListener {
  return async (req, res) => {
    try {
      const response = await handler(toWebRequest(req));
      res.writeHead(response.status, Object.fromEntries(response.headers.entries()));

      if (response.body) {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }
          res.write(value);
        }
      }
      res.end();
    } catch (err) {
      console.error("witness handler threw", err);
      res.statusCode = 500;
      res.end("Internal Server Error");
    }
  };
}
