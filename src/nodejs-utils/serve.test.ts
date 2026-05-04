import assert from "node:assert";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { basename } from "node:path";
import { describe, test } from "node:test";
import type { Logger } from "#keri/logging";
import { createListener, type ListenerOptions } from "./serve.ts";

interface TestServer {
  url: string;
  close(): Promise<void>;
}

async function startServer(
  handler: (request: Request) => Promise<Response>,
  options?: ListenerOptions,
): Promise<TestServer> {
  const server = createServer(createListener(handler, options));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    async close() {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

function makeRecordingLogger(): { logger: Logger; entries: { level: string; msg: string; meta?: object }[] } {
  const entries: { level: string; msg: string; meta?: object }[] = [];
  const make = (level: string) => (msg: string, meta?: object) => {
    entries.push({ level, msg, meta });
  };
  return {
    entries,
    logger: {
      debug: make("debug"),
      info: make("info"),
      warn: make("warn"),
      error: make("error"),
    },
  };
}

function recordRequest(response: Response = new Response(null, { status: 204 })) {
  const captured: { request?: Request } = {};
  const handler = async (req: Request) => {
    captured.request = req;
    return response.clone();
  };
  return { captured, handler };
}

describe(basename(import.meta.url), () => {
  test("forwards method, path, and query to the handler", async () => {
    const { captured, handler } = recordRequest(new Response("ok", { status: 200 }));
    const server = await startServer(handler);
    try {
      const response = await fetch(`${server.url}/foo/bar?x=1&y=2`);
      assert.strictEqual(response.status, 200);
      assert.strictEqual(await response.text(), "ok");
      assert.ok(captured.request);
      assert.strictEqual(captured.request.method, "GET");
      const url = new URL(captured.request.url);
      assert.strictEqual(url.pathname, "/foo/bar");
      assert.strictEqual(url.searchParams.get("x"), "1");
      assert.strictEqual(url.searchParams.get("y"), "2");
    } finally {
      await server.close();
    }
  });

  test("forwards request headers to the handler", async () => {
    const { captured, handler } = recordRequest();
    const server = await startServer(handler);
    try {
      await fetch(`${server.url}/`, {
        headers: { "x-custom-header": "abc", "content-type": "application/json" },
      });
      assert.ok(captured.request);
      assert.strictEqual(captured.request.headers.get("x-custom-header"), "abc");
      assert.strictEqual(captured.request.headers.get("content-type"), "application/json");
    } finally {
      await server.close();
    }
  });

  test("forwards POST body to the handler", async () => {
    let body: string | undefined;
    const server = await startServer(async (req) => {
      body = await req.text();
      return new Response(null, { status: 204 });
    });
    try {
      await fetch(`${server.url}/`, {
        method: "POST",
        body: "hello world",
        headers: { "content-type": "text/plain" },
      });
      assert.strictEqual(body, "hello world");
    } finally {
      await server.close();
    }
  });

  test("does not forward a body for GET requests", async () => {
    const { captured, handler } = recordRequest();
    const server = await startServer(handler);
    try {
      await fetch(`${server.url}/`);
      assert.ok(captured.request);
      assert.strictEqual(captured.request.body, null);
    } finally {
      await server.close();
    }
  });

  test("forwards response status, headers, and body", async () => {
    const server = await startServer(
      async () =>
        new Response("response body", {
          status: 201,
          headers: { "content-type": "text/plain", "x-extra": "value" },
        }),
    );
    try {
      const response = await fetch(`${server.url}/`);
      assert.strictEqual(response.status, 201);
      assert.strictEqual(response.headers.get("content-type"), "text/plain");
      assert.strictEqual(response.headers.get("x-extra"), "value");
      assert.strictEqual(await response.text(), "response body");
    } finally {
      await server.close();
    }
  });

  test("supports streamed response bodies", async () => {
    const server = await startServer(async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("chunk1"));
          controller.enqueue(new TextEncoder().encode("chunk2"));
          controller.close();
        },
      });
      return new Response(stream, { status: 200, headers: { "content-type": "text/plain" } });
    });
    try {
      const response = await fetch(`${server.url}/`);
      assert.strictEqual(await response.text(), "chunk1chunk2");
    } finally {
      await server.close();
    }
  });

  test("returns 500 when the handler throws", async () => {
    const server = await startServer(async () => {
      throw new Error("boom");
    });
    try {
      const response = await fetch(`${server.url}/`);
      assert.strictEqual(response.status, 500);
      assert.strictEqual(await response.text(), "Internal Server Error");
    } finally {
      await server.close();
    }
  });

  test("uses x-forwarded-proto when constructing the request URL", async () => {
    const { captured, handler } = recordRequest();
    const server = await startServer(handler);
    try {
      await fetch(`${server.url}/`, { headers: { "x-forwarded-proto": "https" } });
      assert.ok(captured.request);
      assert.ok(captured.request.url.startsWith("https://"));
    } finally {
      await server.close();
    }
  });

  test("logs request completion at info level with structured meta", async () => {
    const { logger, entries } = makeRecordingLogger();
    const server = await startServer(async () => new Response("ok", { status: 200 }), { logger });
    try {
      await fetch(`${server.url}/some-path?x=1`, { headers: { "x-trace": "abc" } });

      const completed = entries.find((e) => e.level === "info" && e.msg.startsWith("GET /some-path?x=1 200 "));
      assert.ok(completed, "expected an info-level completion log");
      assert.match(completed.msg, /^GET \/some-path\?x=1 200 \d+ms$/);
      const meta = completed.meta as { method: string; url: string; status: number; durationMs: number };
      assert.strictEqual(meta.method, "GET");
      assert.strictEqual(meta.url, "/some-path?x=1");
      assert.strictEqual(meta.status, 200);
      assert.ok(typeof meta.durationMs === "number");
    } finally {
      await server.close();
    }
  });

  test("logs status 500 when the handler throws", async () => {
    const { logger, entries } = makeRecordingLogger();
    const server = await startServer(
      async () => {
        throw new Error("boom");
      },
      { logger },
    );
    try {
      const response = await fetch(`${server.url}/`);
      assert.strictEqual(response.status, 500);

      const errored = entries.find((e) => e.level === "error" && e.msg === "handler threw");
      assert.ok(errored, "expected an error-level log when the handler throws");
      const completed = entries.find((e) => e.level === "info" && e.msg.startsWith("GET / 500 "));
      assert.ok(completed, "expected a completion log with status 500");
    } finally {
      await server.close();
    }
  });
});
