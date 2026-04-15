import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { format } from "node:util";

function toWebRequest(req: IncomingMessage, url: URL): Request {
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

  const request = new Request(url, {
    method: req.method,
    headers: headers,
    body,
    duplex: "half",
    // Cast required because DOM types omit `duplex`, but Node.js undici fetch requires it when body is a stream
  } as RequestInit & { duplex: "half" });

  return request;
}

export interface ServerOptions {
  logger?: (message: string, context?: unknown) => void;
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse<IncomingMessage>,
  handler: (request: Request) => Promise<Response>,
): Promise<void> {
  const host = req.headers.host ?? "0.0.0.0";
  const protocol = req.headers["x-forwarded-proto"] ?? "http";
  const url = new URL(req.url ?? "/", `${protocol}://${host}`);
  const request = toWebRequest(req, url);
  const response = await handler(request);

  res.writeHead(response.status, Object.fromEntries(response.headers.entries()));

  const reader = response.body?.getReader();
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(value);
    }
  }
  res.end();
}

export function createListener(
  handler: (request: Request) => Promise<Response>,
  logger?: (message: string, context?: unknown) => void,
): RequestListener {
  return async (req, res) => {
    const start = Date.now();
    const url = req.url ?? "/";
    const method = req.method ?? "GET";

    res.on("finish", () => {
      const ms = Date.now() - start;

      logger?.(`${method} ${url} - ${res.statusCode} - ${ms}ms`, {
        request: {
          url,
          method,
          headers: req.headers,
        },
        response: {
          status: res.statusCode,
        },
      });
    });

    try {
      await handleRequest(req, res, handler);
    } catch (err) {
      logger?.(`Error handling request\n${format(err)}\n`);
      res.statusCode = 500;
      res.end("Internal Server Error");
    }
  };
}
