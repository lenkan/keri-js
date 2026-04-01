import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { ed25519 } from "@noble/curves/ed25519.js";
import { handle } from "hono/aws-lambda";
import { createApp } from "../src/app.ts";
import { get } from "../src/env.ts";
import { EventStorage } from "../src/event-storage.ts";
import { createSeed } from "../src/seed.ts";
import { createWitness } from "../src/witness.ts";

const tableName = get("DYNAMODB_TABLE_NAME");
const passphrase = get("PASSPHRASE", "password");
const salt = get("SALT", "salt");

const client = new DynamoDBClient();
const storage = new EventStorage({ tableName, client });
const privateKey = ed25519.utils.randomSecretKey(createSeed(passphrase, salt));
const url = get("WITNESS_URL");
const witness = createWitness({ privateKey, url });

function logger(message: string, context: Record<string, unknown>) {
  process.stdout.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      type: "request",
      message,
      record: context,
    })}\n`,
  );
}

const app = createApp({
  witness,
  storage,
  logger,
});

export const handler = handle(app);
