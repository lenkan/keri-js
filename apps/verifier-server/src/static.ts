const CONTENT_TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

/**
 * Maps a request path to a path under the static root, or null if it is not
 * one this server will read. The surface is public and unauthenticated, so
 * anything that could climb out of the root is rejected rather than resolved.
 */
function filePath(pathname: string): string | null {
  let decoded: string;

  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }

  const trimmed = decoded.endsWith("/") ? decoded.slice(0, -1) : decoded;

  if (trimmed === "") {
    return "index.html";
  }

  const segments = trimmed.slice(1).split("/");

  if (segments.some((segment) => segment === "" || segment === "." || segment === ".." || /[\\\0]/.test(segment))) {
    return null;
  }

  return segments.join("/");
}

function hasExtension(path: string): boolean {
  return /\.[^./]+$/.test(path);
}

async function read(path: string): Promise<Uint8Array | null> {
  try {
    return await Deno.readFile(path);
  } catch (cause) {
    if (
      cause instanceof Deno.errors.NotFound ||
      cause instanceof Deno.errors.IsADirectory ||
      cause instanceof Deno.errors.NotADirectory
    ) {
      return null;
    }

    throw cause;
  }
}

function respond(path: string, body: Uint8Array): Response {
  const extension = path.slice(path.lastIndexOf("."));

  // Deno.readFile is typed over ArrayBufferLike, which BodyInit rejects because
  // it admits SharedArrayBuffer. Reading a file never produces one.
  return new Response(body as Uint8Array<ArrayBuffer>, {
    status: 200,
    headers: {
      "Content-Type": CONTENT_TYPES[extension] ?? "application/octet-stream",
      // Vite fingerprints everything it writes under assets/, so those bytes can
      // never change identity. index.html carries the fingerprints and must not.
      "Cache-Control": path.startsWith("assets/") ? "public, max-age=31536000, immutable" : "no-cache",
    },
  });
}

/**
 * Serves the built verifier app out of `root`. Returns null when the request is
 * not ours to answer, which leaves it to the verifier router — including when
 * `root` does not exist at all, as in local dev where vite serves the app.
 */
export function createStaticHandler(root: string): (pathname: string) => Promise<Response | null> {
  return async function serve(pathname: string): Promise<Response | null> {
    const path = filePath(pathname);

    if (!path) {
      return null;
    }

    const file = await read(`${root}/${path}`);

    if (file) {
      return respond(path, file);
    }

    // A path with an extension is a missing asset, not a route: falling back to
    // the app shell there would answer a 404 for a script with HTML.
    if (hasExtension(path)) {
      return null;
    }

    const index = await read(`${root}/index.html`);

    return index ? respond("index.html", index) : null;
  };
}
