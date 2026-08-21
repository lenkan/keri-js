#!/usr/bin/env node
import process from "node:process";
import { DatabaseSync } from "node:sqlite";
import { Controller } from "@keri-js/infra/controller";
import { NodeSqliteDatabase } from "@keri-js/infra/node";
import { SqliteControllerStorage } from "@keri-js/infra/sqlite";
import { execute } from "./cli.ts";
import { resolveInputStream } from "./input.ts";

try {
  await execute({
    args: process.argv.slice(2),
    read: resolveInputStream,
    controller: async () => {
      const database = new DatabaseSync(process.env.KERI_DB ?? "keri.db");
      const storage = new SqliteControllerStorage(new NodeSqliteDatabase(database));
      return new Controller({ storage, passphrase: process.env.KERI_PASSPHRASE });
    },
  });
} catch (error) {
  if (error instanceof Error) {
    process.stderr.write("Error: ");
    process.stderr.write(error.message);
    process.stderr.write("\n");
  }
  process.exit(1);
}
