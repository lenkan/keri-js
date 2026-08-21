/** biome-ignore-all lint/suspicious/noConsole: server entrypoint */
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { styleText } from "node:util";
import { createMailboxRouter, Mailbox } from "@keri-js/infra/mailbox";
import { createListener, NodeSqliteDatabase } from "@keri-js/infra/node";
import { SqliteControllerStorage } from "@keri-js/infra/sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";
import { scrypt } from "@noble/hashes/scrypt.js";

// KERI_DB points at a file for state that survives restarts; the in-memory
// default keeps dev runs disposable.
const storage = new SqliteControllerStorage(
  new NodeSqliteDatabase(new DatabaseSync(process.env.KERI_DB ?? ":memory:")),
);

const port = parseInt(process.env.PORT ?? "3000", 10);
const passphrase = process.env.PASSPHRASE ?? "password";
const salt = process.env.SALT ?? "salt";
const url = process.env.MAILBOX_URL ?? `http://localhost:${port}`;

const seed = scrypt(passphrase, salt, { N: 16384, r: 8, p: 1, dkLen: 32 });
const privateKey = ed25519.utils.randomSecretKey(seed);
const mailbox = await Mailbox.create({ privateKey, url, storage, logger: console });

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
