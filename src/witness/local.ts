/** biome-ignore-all lint/suspicious/noConsole: Development */

import { DatabaseSync } from "node:sqlite";
import { styleText } from "node:util";
import { serve } from "@hono/node-server";
import { ed25519 } from "@noble/curves/ed25519.js";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../storage/sqlite/storage-sqlite.ts";
import { createApp } from "./app.ts";
import { get } from "./env.ts";
import { createSeed } from "./seed.ts";
import { Witness } from "./witness.ts";

const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));

const port = parseInt(get("PORT", "3000"), 10);
const passphrase = get("PASSPHRASE", "password");
const salt = get("SALT", "salt");
const url = get("WITNESS_URL", `http://localhost:${port}`);

const privateKey = ed25519.utils.randomSecretKey(createSeed(passphrase, salt));
const witness = new Witness({ privateKey, url, storage });

const app = createApp({
  witness,
  logger: (message) => console.log(message),
});

const server = serve({ fetch: app.fetch, port }, (info) => {
  console.log(
    [
      "",
      styleText("green", "Witness running at:"),
      styleText("cyan", `  http://localhost:${info.port}`),
      styleText("cyan", `  http://localhost:${info.port}/oobi`),
      styleText("cyan", `  http://localhost:${info.port}/oobi/${witness.aid}`),
      "",
      styleText("yellow", "Press Ctrl+C to stop"),
      "",
    ].join("\n"),
  );
});

process.on("SIGTERM", () => {
  server.close();
});
