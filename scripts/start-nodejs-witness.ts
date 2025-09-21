import { serve } from "@hono/node-server";
import { scrypt } from "@noble/hashes/scrypt.js";
import { Witness } from "../src/witness.ts";

function createSeed(init: string): Uint8Array {
  return scrypt(init, "salt", { N: 16384, r: 8, p: 1, dkLen: 32 });
}

const port = parseInt(process.env.PORT ?? "5631");
const url = `http://localhost:${port}`;

const witness = new Witness({
  seed: createSeed("witness"),
  url,
});

const server = serve(
  {
    fetch: (req) => witness.fetch(req),
    port,
  },
  () => {
    console.log(`KERI witness demo started on ${url}`);
    console.log(`AID: ${witness.state.i}`);
    console.log(`OOBI URL: ${url}/oobi/${witness.state.i}`);
  },
);

server.on("error", (err) => {
  console.error("Error starting server:", err);
  process.exit(1);
});
