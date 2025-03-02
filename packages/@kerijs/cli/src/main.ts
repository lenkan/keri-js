#!/usr/bin/env node
import { program } from "commander";
import type { InceptEvent } from "keri";
import { parse, FileSystemKeyStore, Habitat, keri } from "keri";
import { SqliteEventStore } from "@kerijs/db-sqlite";

const db = new SqliteEventStore({ filename: ".keri/db.sqlite" });
db.init();

program.command("parse").action(async () => {
  const stream = process.stdin;

  for await (const event of parse(ReadableStream.from(stream))) {
    console.log(event);
  }
});

program
  .command("keygen")
  .requiredOption("--passcode <passcode>")
  .action(async ({ passcode }) => {
    const keystore = new FileSystemKeyStore({ dir: ".keri/keys", passphrase: passcode });

    await keystore.incept();
  });

program.command("resolve <oobi>").action(async (oobi) => {
  const response = await fetch(oobi);
  if (!response.ok) {
    throw new Error(`Failed to fetch oobi: ${response.status} ${response.statusText}`);
  }

  if (!response.body) {
    throw new Error(`No body in response`);
  }

  for await (const event of parse(response.body)) {
    db.saveEvent(event.payload as InceptEvent);
  }
});

program
  .command("incept")
  .requiredOption("--passcode <passcode>")
  .option("--wit <wit>")
  .action(async ({ passcode, wit }) => {
    if (typeof passcode !== "string") {
      throw new Error(`Invalid passcode`);
    }

    const keystore = new FileSystemKeyStore({ dir: ".keri/keys", passphrase: passcode });

    const hab = new Habitat({ db, keystore });

    const wits: string[] = [];

    if (typeof wit === "string") {
      wits.push(wit);
    }

    const key = await keystore.incept();
    const event = keri.incept({ b: wits, k: [key.current], n: [key.next] });
    const signature = await keystore.sign(key.current, new TextEncoder().encode(JSON.stringify(event)));
    await hab.create(event, [signature]);

    console.dir(await hab.list(event.i), { depth: 100 });
  });

program
  .command("interact")
  .requiredOption("--passcode <passcode>")
  .requiredOption("--aid <aid>")
  .action(async ({ passcode, aid }) => {
    if (typeof passcode !== "string") {
      throw new Error(`Invalid passcode`);
    }

    if (typeof aid !== "string") {
      throw new Error(`Invalid aid`);
    }

    const keystore = new FileSystemKeyStore({ dir: ".keri/keys", passphrase: passcode });

    const hab = new Habitat({ db, keystore });
    const payload = await hab.interact(aid);

    console.dir(payload);
  });

program.command("export").action(async () => {
  for (const event of await db.list()) {
    console.log(event);
  }
});

program.parse(process.argv);
