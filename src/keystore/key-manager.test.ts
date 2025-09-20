import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";
import { setTimeout } from "node:timers/promises";
import { KeyManager, verify } from "./key-manager.ts";
import { PassphraseEncrypter } from "../main.ts";

const map = new Map<string, string>();

const keystore = new KeyManager({
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

beforeEach(() => {
  map.clear();
});

test("Incept should create new key sequence", async () => {
  const key = await keystore.incept();

  assert(typeof key.current === "string");
  assert(typeof key.next === "string");
});

test("Can create signature", async () => {
  const key = await keystore.incept();

  const data = crypto.getRandomValues(new Uint8Array(32));
  const signature = await keystore.sign(key.current, data);

  assert(typeof signature === "string");
});

test("Can create and verify signature", async () => {
  const key = await keystore.incept();

  const data = crypto.getRandomValues(new Uint8Array(32));
  const signature = await keystore.sign(key.current, data);

  const result = verify(key.current, data, signature);

  assert.equal(result, true);
});
