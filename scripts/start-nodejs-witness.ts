import { serve } from "@hono/node-server";

import { Witness } from "../src/witness.ts";

const witness = new Witness();

const port = parseInt(process.env.PORT ?? "5631");

try {
  serve({
    fetch: (req) => witness.fetch(req),
    port,
  });
} catch (error) {
  console.error("Error starting KERI witness demo:", error);
} finally {
  console.log(`KERI witness demo started on port http://localhost:${port}`);
}
