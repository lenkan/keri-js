import assert from "node:assert";
import test, { after, before } from "node:test";
import { KeyEventLog } from "../src/core/main.ts";
import { createController, type KeripyWitness, startKeripyWitness } from "./utils.ts";

let wan: KeripyWitness;
const abortController = new AbortController();

before(async () => {
  wan = await startKeripyWitness({ signal: abortController.signal });
});

after(() => {
  abortController.abort();
});

// Interop: a KERIjs delegator and a KERIjs delegate run the full delegated
// inception protocol against a KERIpy witness. The delegate builds a `dip`,
// the delegator anchors it with an `ixn`, the delegate attaches the
// resulting SealSourceCouple, and both events are received and stored by
// the KERIpy witness. Verifies KERIjs-produced delegated identifiers are
// accepted by KERIpy.
test("KERIjs delegator + delegate produce a delegation accepted by a KERIpy witness", async () => {
  const delegator = createController();
  const delegate = createController();

  await delegator.introduce(wan.oobi);
  await delegate.introduce(wan.oobi);

  const delegatorState = await delegator.incept({ wits: [wan.aid], toad: 1 });

  // Delegate builds a dip referencing the delegator; it isn't submitted yet
  // because witnesses won't accept a dip without a SealSourceCouple.
  const { id: delegateAid, event: dip } = await delegate.delegatedIncept({
    delegator: delegatorState.id,
    wits: [wan.aid],
    toad: 1,
  });

  // Delegator anchors the dip in its KEL via an interaction event whose `a`
  // carries a seal pointing at the dip (i, s, d).
  const { event: ixn } = await delegator.anchor(delegatorState.id, {
    data: { i: delegateAid, s: dip.body.s, d: dip.body.d },
  });

  // Delegate attaches the SealSourceCouple from the delegator's anchoring
  // ixn and commits the dip to its witnesses.
  dip.attachments.SealSourceCouples.push({ snu: ixn.s, digest: ixn.d });
  await delegate.commit(KeyEventLog.empty(), dip);

  // Fetching the delegate's KEL from the KERIpy witness must return a stream
  // that KERIjs can parse end-to-end: it splits the multi-AID stream, builds
  // the delegator KEL first, and verifies the dip's anchor against it.
  const response = await fetch(`${wan.url}/oobi/${delegateAid}`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected delegate OOBI response from KERIpy witness");

  const log = await KeyEventLog.parse(response.body, { allowPartiallyWitnessed: true });
  assert.equal(log.state.identifier, delegateAid);
  assert.equal(log.state.delegator, delegatorState.id);
  assert.equal(log.state.lastEvent.s, "0");
  assert.equal(log.events[0].body.t, "dip");

  assert.ok(log.delegator, "Expected the parsed delegate KEL to carry its delegator KEL");
  assert.equal(log.delegator.state.identifier, delegatorState.id);
  assert.ok(
    log.delegator.events.some((e) => e.body.t === "ixn"),
    "Expected delegator KEL on the KERIpy witness to contain the anchoring ixn",
  );
});
