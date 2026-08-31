import test, { after } from "node:test";
import { KERIPy } from "../test_utils/keripy.ts";
import { startWitness, type WitnessEndpoint } from "./utils.ts";

/**
 * Mailbox delivery between two KERIpy controllers whose only infrastructure is
 * this witness. A challenge response is the cheapest round trip that uses one:
 * `challenge respond` forwards an `exn` into the recipient's mailbox and
 * `challenge verify` polls it back out, so a pass covers the `exn /fwd` intake,
 * the ordinal allocation, the signed `qry mbx` and the SSE framing of the reply.
 *
 * The witness is the mailbox here, as it is in KERIpy — there is no separate
 * mailbox service to resolve.
 */

const abortController = new AbortController();

after(() => {
  abortController.abort();
});

/** A KERIpy controller inceptioned against the given witnesses. */
async function controller(wits: WitnessEndpoint[]): Promise<{ keripy: KERIPy; aid: string }> {
  const keripy = new KERIPy();
  await keripy.init();
  for (const [index, wit] of wits.entries()) {
    await keripy.oobi.resolve(wit.oobi, `wit${index}`);
  }
  await keripy.incept({
    wits: wits.map((wit) => wit.aid),
    toad: wits.length,
    receiptEndpoint: true,
  });
  // Authorizes each witness to hold this controller's mailbox. KERIpy senders
  // read this role off the recipient's OOBI to decide between a direct send and
  // an `exn /fwd` deposit.
  for (const wit of wits) {
    await keripy.ends.add({ eid: wit.aid, role: "mailbox" });
  }
  return { keripy, aid: await keripy.aid() };
}

test("KERIpy delivers a challenge response through a witness mailbox", async () => {
  const wan = await startWitness({ signal: abortController.signal });

  const alice = await controller([wan]);
  const bob = await controller([wan]);

  // The role-scoped OOBI form. A bare `/oobi/{aid}` matches KERIpy's SAID
  // pattern instead and never binds an end role, so the sender would fall back
  // to a direct send.
  await alice.keripy.oobi.resolve(`${wan.url}/oobi/${bob.aid}/mailbox`, "bob");
  await bob.keripy.oobi.resolve(`${wan.url}/oobi/${alice.aid}/mailbox`, "alice");

  const words = await bob.keripy.challenge.generate();

  // Deposits an `exn` into bob's mailbox on wan.
  await alice.keripy.challenge.respond({ words, recipient: "bob" });

  // Polls that mailbox with a signed `qry mbx` and verifies the signature.
  await bob.keripy.challenge.verify({ words, signer: "alice" });
});

test("KERIpy delivers a challenge response between controllers on separate witnesses", async () => {
  const wan = await startWitness({ signal: abortController.signal });
  const wil = await startWitness({ signal: abortController.signal });

  const alice = await controller([wan]);
  const bob = await controller([wil]);

  // Neither controller has the other's witness in its habitat, so the mailbox
  // OOBI is the only thing that points the sender at the right witness.
  await alice.keripy.oobi.resolve(`${wil.url}/oobi/${bob.aid}/mailbox`, "bob");
  await bob.keripy.oobi.resolve(`${wan.url}/oobi/${alice.aid}/mailbox`, "alice");

  const words = await bob.keripy.challenge.generate();

  await alice.keripy.challenge.respond({ words, recipient: "bob" });

  await bob.keripy.challenge.verify({ words, signer: "alice" });
});
