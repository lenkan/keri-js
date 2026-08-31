import assert from "node:assert";
import test, { after } from "node:test";
import { parse } from "../src/cesr/main.ts";
import { KERIPy } from "../test_utils/keripy.ts";
import { startWitness } from "./utils.ts";

/**
 * A KERIpy controller against this witness, driven only through its HTTP API.
 * `kli` resolves the witness by OOBI, inceptions against it, and collects the
 * receipt — which is the whole contract `POST /receipts` and `GET /oobi` exist
 * to satisfy.
 */

const abortController = new AbortController();

after(() => {
  abortController.abort();
});

test("KERIpy creates an identifier with a single witness", async () => {
  const wan = await startWitness({ signal: abortController.signal });

  const keripy = new KERIPy();
  await keripy.init();
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.incept({ wits: [wan.aid], toad: 1, receiptEndpoint: true });

  const aid = await keripy.aid();

  const response = await fetch(`${wan.url}/oobi/${aid}`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected response body");

  const parsed = await Array.fromAsync(parse(response.body));
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.body.i, aid);
  assert.equal(parsed[0].attachments.ControllerIdxSigs.length, 1);
  assert.equal(parsed[0].attachments.WitnessIdxSigs.length, 1);
});

test("KERIpy collects a receipt from each of two witnesses", async () => {
  const wan = await startWitness({ signal: abortController.signal });
  const wil = await startWitness({ signal: abortController.signal });

  const keripy = new KERIPy();
  await keripy.init();
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.oobi.resolve(wil.oobi, "wil");
  await keripy.incept({ wits: [wan.aid, wil.aid], toad: 2, receiptEndpoint: true });

  const aid = await keripy.aid();

  // Each witness stores only its own signature: KERIpy posts the cross-receipts
  // back with no couples attached, so the merge never has anything to merge.
  for (const witness of [wan, wil]) {
    const response = await fetch(`${witness.url}/oobi/${aid}`);
    assert.equal(response.status, 200);
    assert(response.body, "Expected response body");

    const parsed = await Array.fromAsync(parse(response.body));
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]?.body.i, aid);
  }

  // KERIpy's own KEL is where reaching toad=2 shows: it addresses each backer
  // with its own request, so both receipts have to come back attributed
  // correctly for it to count them.
  const own = await Array.fromAsync(parse(await keripy.export()));
  assert.equal(own.length, 1);
  assert.equal(own[0].attachments.WitnessIdxSigs.length, 2, "KERIpy collected a receipt from both witnesses");
});
