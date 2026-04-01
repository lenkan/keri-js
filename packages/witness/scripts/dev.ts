import { styleText } from "node:util";
import { serve } from "@hono/node-server";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createApp } from "../src/app.ts";
import { createTable } from "../src/dynamo-client.ts";
import { get } from "../src/env.ts";
import { EventStorage } from "../src/event-storage.ts";
import { createSeed } from "../src/seed.ts";
import { createWitness } from "../src/witness.ts";

const port = parseInt(get("PORT", "3000"), 10);
const tableName = get("DYNAMODB_TABLE_NAME");
const endpoint = get("DYNAMODB_ENDPOINT");
const passphrase = get("PASSPHRASE", "password");
const salt = get("SALT", "salt");

const dynamo = await createTable(tableName, endpoint);
const storage = new EventStorage({ tableName, client: dynamo });

const witness = createWitness({
  privateKey: ed25519.utils.randomSecretKey(createSeed(passphrase, salt)),
  url: `http://localhost:${port}`,
});

const app = createApp({
  witness,
  storage,
  logger: (message, context) => {
    console.log(message);
    console.dir({ time: new Date().toISOString(), ...context }, { depth: 100 });
  },
});

const server = serve(
  {
    fetch: app.fetch,
    port,
  },
  (info) => {
    console.log(
      [
        "",
        styleText("green", "🚀 Server running at:"),
        styleText("cyan", `  🌐 http://localhost:${info.port}`),
        styleText("cyan", `  🌐 http://localhost:${info.port}/oobi`),
        styleText("cyan", `  🌐 http://localhost:${info.port}/oobi/${witness.aid}`),
        "",
        styleText("yellow", "Press Ctrl+C to stop the server"),
        "",
      ].join("\n"),
    );
  },
);

process.on("SIGTERM", () => {
  console.log(["", styleText("yellow", "🛑 SIGTERM received, shutting down server..."), ""].join("\n"));
  server.close();
});
