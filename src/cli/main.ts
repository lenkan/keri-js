#!/usr/bin/env -S node --no-warnings
import { program } from "commander";
import { Controller } from "../controller.ts";
import { SqliteStorage } from "../db/storage-sqlite.ts";
import { KeyManager } from "../keystore/key-manager.ts";
import { keri, type CredentialEvent } from "../events/events.ts";
import { PassphraseEncrypter } from "../keystore/encrypt.ts";
import { Message } from "cesr";

const storage = new SqliteStorage({ filename: ".keri/db.sqlite" });
storage.init();

function getStringArray(options: unknown, key: string): string[] {
  if (typeof options !== "object" || options === null || !(key in options)) {
    return [];
  }

  const value = options[key];
  const result: string[] = [];

  if (typeof value === "string") {
    result.push(value);
  } else if (Array.isArray(value)) {
    result.push(...value);
  }

  return result;
}

function getOptionalString(options: unknown, key: string): string | undefined {
  if (typeof options !== "object" || options === null) {
    throw new Error(`Options is not an object`);
  }

  const value = options[key];

  if (value !== undefined && typeof value !== "string") {
    throw new Error(`Expected "${key}" to be a string, got "${typeof value}"`);
  }

  return value;
}

function getString(options: unknown, key: string): string {
  const value = getOptionalString(options, key);

  if (!value) {
    throw new Error(`Expected "${key}" to be a string, got "${value}"`);
  }

  return value;
}

program.command("resolve <oobi>").action(async (oobi) => {
  const controller = new Controller({
    storage,
    keyManager: new KeyManager({ storage, encrypter: new PassphraseEncrypter("") }),
  });

  await controller.resolve(oobi);
});

program
  .command("incept")
  .requiredOption("--passcode <passcode>")
  .option("--wit <wit...>")
  .action(async (options) => {
    const passcode = getString(options, "passcode");
    const wits = getStringArray(options, "wit");

    const encrypter = new PassphraseEncrypter(passcode);
    const keystore = new KeyManager({ encrypter, storage });
    const controller = new Controller({ storage, keyManager: keystore });

    const event = await controller.createIdentifier({ wits });

    console.log(event.i);
  });

program
  .command("send")
  .description("Sends a signed exchange message to the specified recipient")
  .requiredOption("--sender <sender aid>")
  .requiredOption("--route <route>")
  .requiredOption("--topic <topic>")
  .requiredOption("--receiver <receiver aid>")
  .requiredOption("--passcode <passcode>")
  .requiredOption("--data <data>")
  .action(async (options) => {
    const passcode = getString(options, "passcode");
    const sender = getString(options, "sender");
    const receiver = getString(options, "receiver");
    const route = getString(options, "route");
    const topic = getString(options, "topic");
    const data = JSON.parse(getString(options, "data"));

    const keystore = new KeyManager({
      storage,
      encrypter: new PassphraseEncrypter(passcode),
    });

    const controller = new Controller({ storage, keyManager: keystore });
    const client = await controller.getClient(receiver);
    const message = new Message(
      keri.exchange({
        i: sender,
        r: route,
        q: {},
        a: { i: sender, ...data },
        e: {},
      }),
    );

    await controller.forward(client, {
      sender: await controller.state(sender),
      topic,
      recipient: receiver,
      message,
    });
  });

program
  .command("create-registry")
  .description("Creates a new credential registry")
  .requiredOption("--owner <owner aid>")
  .requiredOption("--passcode <passcode>")
  .action(async (options) => {
    const passcode = getString(options, "passcode");
    const owner = getString(options, "owner");

    const keystore = new KeyManager({
      storage,
      encrypter: new PassphraseEncrypter(passcode),
    });

    const controller = new Controller({ storage, keyManager: keystore });

    const registry = await controller.createRegistry({ owner });
    console.log(registry.i);
  });

program
  .command("create-credential")
  .description("Creates a new credential")
  .requiredOption("--registry <registry said>")
  .requiredOption("--receiver <receiver aid>")
  .requiredOption("--schema <schema said>")
  .requiredOption("--data <data>")
  .requiredOption("--rules <rules>")
  .option("--salt <salt>")
  .option("--edges <edges>")
  .requiredOption("--passcode <passcode>")
  .action(async (options) => {
    const passcode = getString(options, "passcode");
    const registryId = getString(options, "registry");
    const receiver = getString(options, "receiver");
    const schemaId = getString(options, "schema");
    const salt = getOptionalString(options, "salt");
    const data = JSON.parse(getString(options, "data"));
    const rules = JSON.parse(getString(options, "rules"));
    const edges = JSON.parse(getOptionalString(options, "edges") ?? "null");

    const keystore = new KeyManager({
      storage,
      encrypter: new PassphraseEncrypter(passcode),
    });

    const controller = new Controller({ storage, keyManager: keystore });

    const acdc = await controller.createCredential({
      holder: receiver,
      registryId: registryId,
      schemaId: schemaId,
      data: data,
      salt: salt,
      rules: rules,
      edges: edges || undefined,
    });

    const s = await controller.store.get(acdc.d);
    if (!s) {
      throw new Error("Failed to store created credential");
    }

    console.log(acdc.d);
  });

program
  .command("ipex-grant")
  .requiredOption("--said <aid>")
  .requiredOption("--passcode <passcode>")
  .action(async (options) => {
    const passcode = getString(options, "passcode");
    const said = getString(options, "said");

    const keystore = new KeyManager({
      storage,
      encrypter: new PassphraseEncrypter(passcode),
    });

    const controller = new Controller({
      storage,
      keyManager: keystore,
    });

    const acdc = (await controller.store.get(said))?.payload as unknown as CredentialEvent;
    if (!acdc) {
      throw new Error(`No ACDC found for said ${said}`);
    }

    if (acdc.a.i) {
      await controller.sendCredentialArficats(acdc, acdc.a.i);
    }

    await controller.grant({
      credential: acdc,
    });
  });

program.parse(process.argv);
