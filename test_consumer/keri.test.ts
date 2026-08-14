import assert from "node:assert";
import { after, before, describe, test } from "node:test";
import { parse } from "cesr";
import { collectAsync, createController, type Endpoint, startMailbox, startWitness } from "./utils.ts";

const abortController = new AbortController();

let witness: Endpoint;
let mailbox: Endpoint;

before(async () => {
  witness = await startWitness(abortController.signal);
  mailbox = await startMailbox(abortController.signal);
});

after(() => {
  abortController.abort();
});

describe("keri", () => {
  test("incepts an identifier backed by sqlite storage", async () => {
    const controller = createController();
    const { id, event } = await controller.incept();

    assert.equal(event.i, id);
    assert.equal(event.t, "icp");

    const events = await controller.export(id);
    assert.equal(events.length, 1);

    const log = await controller.loadEventLog(id);
    assert.equal(log.state.identifier, id);
  });
});

describe("keri/witness", () => {
  test("serves an oobi for itself", async () => {
    const response = await fetch(witness.oobi);

    assert.equal(response.status, 200);
    assert(response.body, "Expected response body");

    const messages = await collectAsync(parse(response.body));
    assert(messages.some((message) => message.body.i === witness.aid));
  });

  test("receipts an inception event it backs", async () => {
    const controller = createController();
    await controller.introduce(witness.oobi);

    const { id } = await controller.incept({ wits: [witness.aid], toad: 1 });

    const response = await fetch(`${witness.url}/oobi/${id}`);
    assert.equal(response.status, 200);
    assert(response.body, "Expected response body");

    const messages = await collectAsync(parse(response.body));
    assert.equal(messages.length, 1);
    assert.equal(messages[0]?.body.i, id);
    assert.equal(messages[0].attachments.WitnessIdxSigs.length, 1);
  });
});

describe("keri/mailbox", () => {
  test("serves an oobi for itself", async () => {
    const response = await fetch(mailbox.oobi);

    assert.equal(response.status, 200);
    assert(response.body, "Expected response body");

    const messages = await collectAsync(parse(response.body));
    assert(messages.some((message) => message.body.i === mailbox.aid));
  });
});
