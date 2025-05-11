import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout } from "node:timers/promises";
import { KeyStore } from "./keystore.ts";
import { PassphraseEncrypter } from "../main.ts";

test("Incept and sign with async key store", async () => {
  const map = new Map<string, string>();

  const keystore = new KeyStore({
    encrypter: new PassphraseEncrypter("password"),
    storage: {
      async get(key) {
        return map.get(key) ?? null;
      },
      async set(key, value) {
        await setTimeout(1);
        map.set(key, value);
      },
    },
  });

  const key = await keystore.incept();
  const signature = await keystore.sign(key.current, new Uint8Array(32));

  assert(typeof signature === "string");
});
