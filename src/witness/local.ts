/** biome-ignore-all lint/suspicious/noConsole: Development */
import { styleText } from "node:util";
import { serve } from "@hono/node-server";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createApp } from "./app.ts";
import { get } from "./env.ts";
import type { EventStorage, ListEventArgs } from "./event-storage.ts";
import { createSeed } from "./seed.ts";
import type { WitnessEvent } from "./witness.ts";
import { createWitness } from "./witness.ts";

class MemoryEventStorage implements EventStorage {
  private readonly events = new Map<string, WitnessEvent[]>();

  async saveEvent(event: WitnessEvent): Promise<void> {
    const key = (event.message.body as { i?: string }).i ?? "";
    const existing = this.events.get(key) ?? [];
    existing.push(event);
    this.events.set(key, existing);
  }

  async listEvents(args: ListEventArgs): Promise<WitnessEvent[]> {
    return this.events.get(args.i) ?? [];
  }
}

const port = parseInt(get("PORT", "3000"), 10);
const passphrase = get("PASSPHRASE", "password");
const salt = get("SALT", "salt");
const url = get("WITNESS_URL", `http://localhost:${port}`);

const storage = new MemoryEventStorage();
const privateKey = ed25519.utils.randomSecretKey(createSeed(passphrase, salt));
const witness = createWitness({ privateKey, url });

const app = createApp({
  witness,
  storage,
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
