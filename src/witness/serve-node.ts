/** biome-ignore-all lint/suspicious/noConsole: Development */

import { createServer, type IncomingHttpHeaders, type IncomingMessage } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { Readable } from "node:stream";
import { styleText } from "node:util";
import { ed25519 } from "@noble/curves/ed25519.js";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../storage/sqlite/storage-sqlite.ts";
import { get } from "./env.ts";
import { createSeed } from "./seed.ts";
import { Witness } from "./witness.ts";
import { createRouter } from "./witness-router.ts";

const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));

const port = parseInt(get("PORT", "3000"), 10);
const passphrase = get("PASSPHRASE", "password");
const salt = get("SALT", "salt");
const url = get("WITNESS_URL", `http://localhost:${port}`);

const privateKey = ed25519.utils.randomSecretKey(createSeed(passphrase, salt));
const witness = new Witness({ privateKey, url, storage });

const handler = createRouter(witness);

function toWebHeaders(reqHeaders: IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(reqHeaders)) {
    if (value !== undefined) {
      if (Array.isArray(value)) {
        for (const v of value) {
          headers.append(key, v);
        }
      } else {
        headers.set(key, value);
      }
    }
  }
  return headers;
}

function toWebBody(req: IncomingMessage): BodyInit | null {
  if (req.method === "HEAD" || req.method === "GET") {
    return null;
  }
  return Readable.toWeb(req) as ReadableStream<Uint8Array>;
}

function toWebRequest(req: IncomingMessage): Request {
  const { method, url, headers } = req;
  const host = headers.host ?? `localhost:${port}`;
  return new Request(`http://${host}${url ?? "/"}`, {
    method,
    headers: toWebHeaders(headers),
    body: toWebBody(req),
  });
}

const server = createServer(async (req, res) => {
  const start = Date.now();
  const url = req.url ?? "/";
  const method = req.method ?? "GET";
  res.on("finish", () => {
    const ms = Date.now() - start;
    console.log(`${method} ${url} - ${res.statusCode} - ${ms}ms`, {
      request: {
        url,
        method,
        headers: req.headers,
      },
      response: {
        status: res.statusCode,
        headers: res.getHeaders(),
      },
    });
  });

  try {
    const request = toWebRequest(req);
    const response = await handler(request);

    res.writeHead(response.status, Object.fromEntries(response.headers));
    const reader = response.body?.getReader();
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
    }
    res.end();
  } catch (err) {
    console.error("Error handling request:", err);
    res.statusCode = 500;
    res.end("Internal Server Error");
  }
});

server.listen(port, () => {
  console.log(
    [
      "",
      styleText("green", "Witness running at:"),
      styleText("cyan", `  http://localhost:${port}`),
      styleText("cyan", `  http://localhost:${port}/oobi`),
      styleText("cyan", `  http://localhost:${port}/oobi/${witness.aid}`),
      "",
      styleText("yellow", "Press Ctrl+C to stop"),
      "",
    ].join("\n"),
  );
});

process.on("SIGTERM", () => {
  server.close();
});
