import assert from "node:assert";
import test, { after, before } from "node:test";
import { parse } from "#keri/cesr";
import { KERIPy } from "./keripy.ts";
import { collectAsync, type Endpoint, startKerijsWitness } from "./utils.ts";

let wan: Endpoint;
let wil: Endpoint;
const abortController = new AbortController();

before(async () => {
  [wan, wil] = await Promise.all([
    startKerijsWitness({ signal: abortController.signal }),
    startKerijsWitness({ signal: abortController.signal }),
  ]);
});

after(() => {
  abortController.abort();
});

test("KERIpy creates identifier with single KERIjs witness", async () => {
  const keripy = new KERIPy();
  await keripy.init();
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.incept({ wits: [wan.aid], toad: 1, receiptEndpoint: true });

  const aid = await keripy.aid();

  const response = await fetch(`${wan.url}/oobi/${aid}`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected response body");

  const parsed = await collectAsync(parse(response.body));
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.body.i, aid);
  assert.equal(parsed[0].attachments.ControllerIdxSigs.length, 1);
  assert.equal(parsed[0].attachments.WitnessIdxSigs.length, 1);
});

test("KERIpy creates identifier with two KERIjs witnesses", async () => {
  const keripy = new KERIPy();
  await keripy.init();
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.oobi.resolve(wil.oobi, "wil");
  await keripy.incept({ wits: [wan.aid, wil.aid], toad: 2, receiptEndpoint: true });

  const aid = await keripy.aid();

  const [response1, response2] = await Promise.all([fetch(`${wan.url}/oobi/${aid}`), fetch(`${wil.url}/oobi/${aid}`)]);

  assert.equal(response1.status, 200);
  assert.equal(response2.status, 200);
});
