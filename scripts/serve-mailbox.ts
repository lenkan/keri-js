import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { styleText } from "node:util";
import { ed25519 } from "@noble/curves/ed25519.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { createMailboxRouter, Mailbox } from "../src/mailbox/main.ts";
import { createListener } from "../src/nodejs-utils/serve.ts";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../src/storage/sqlite/storage-sqlite.ts";

const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));

const port = parseInt(process.env.PORT ?? "3000", 10);
const passphrase = process.env.PASSPHRASE ?? "password";
const salt = process.env.SALT ?? "salt";
const url = process.env.MAILBOX_URL ?? `http://localhost:${port}`;

const seed = scrypt(passphrase, salt, { N: 16384, r: 8, p: 1, dkLen: 32 });
const privateKey = ed25519.utils.randomSecretKey(seed);
const mailbox = new Mailbox({ privateKey, url, storage, logger: console });

const router = createMailboxRouter(mailbox, { logger: console });
const server = createServer(createListener(router, { logger: console }));

server.listen(port, () => {
  console.log(
    [
      "",
      styleText("green", "Mailbox running at:"),
      styleText("cyan", `  http://localhost:${port}`),
      styleText("cyan", `  http://localhost:${port}/oobi`),
      "",
      styleText("yellow", "Press Ctrl+C to stop"),
      "",
    ].join("\n"),
  );
});

function shutdown() {
  console.log("\nShutting down mailbox...");
  server.close(() => {
    console.log("Mailbox stopped.");
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
