import assert from "node:assert";
import { basename } from "node:path";
import { describe, mock, test } from "node:test";
import { signRaw } from "../../test_utils/signing.ts";
import { Message } from "../cesr/main.ts";
import {
  endorse,
  generateKeyPair,
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  RoutedEvent,
  verifySignature,
} from "../main.ts";
import { MemoryStore } from "./memory-store.ts";
import type { Store } from "./store.ts";
import { Witness } from "./witness.ts";
import { WitnessError } from "./witness-error.ts";
import { WitnessStorage } from "./witness-storage.ts";

function makeWitness(store: Store = new MemoryStore()) {
  return new Witness({
    privateKey: generateKeyPair({ insecureSeed: "test-witness" }).privateKey,
    store,
  });
}

/** A transferable controller, plus the signer material needed to endorse as it. */
function makeController(wits: string[] = []) {
  const key = generateKeyPair();
  const next = generateKeyPair();
  const icp = KeyEvent.incept({
    signingKeys: [key.publicKey],
    nextKeyDigests: [next.publicKey],
    backers: wits,
  });
  const message = new Message(icp.body, { ControllerIdxSigs: [signRaw(icp.raw, key.privateKey, 0)] });
  const kel = KeyEventLog.from([message], { allowPartiallyWitnessed: true });

  // A `KeyPair` is its own `Signer`, so nothing has to be rebuilt to endorse.
  return { aid: kel.state.identifier, state: kel.state, message, signer: key };
}

/** The `rct` another witness would post here, receipting `icp` with its own key. */
function receiptFrom(icp: Message, key: { privateKey: Uint8Array; publicKey: string }): Message {
  const rct = KeyEvent.receipt(icp as Message<KeyEventBody>);
  return new Message(rct.body, {
    NonTransReceiptCouples: [{ prefix: key.publicKey, sig: signRaw(icp.raw, key.privateKey) }],
  });
}

type Controller = ReturnType<typeof makeController>;

/** Registers the controller with the witness the only way that matters: by being receipted. */
async function backedBy(witness: Witness): Promise<Controller> {
  const controller = makeController([witness.aid]);
  await witness.receipt(controller.message);
  return controller;
}

function forwardTo(pre: string, topic: string, payload: Message) {
  return RoutedEvent.exchange({
    sender: pre,
    route: "/fwd",
    query: { pre, topic },
    embeds: { evt: payload },
  });
}

function pollFor(controller: Controller, src: string, topics: Record<string, number>, as: Controller = controller) {
  const message = RoutedEvent.query({
    r: "mbx",
    q: { src, i: controller.aid, topics },
  });
  return endorse(message, { signers: [as.signer], state: as.state, latest: true });
}

/** Any message is a valid mailbox payload; an icp is the cheapest one to make. */
function payload() {
  return makeController().message;
}

/** Rewrites the AID a signature group claims to belong to, leaving the signature itself alone. */
function claimPrefix(message: Message, prefix: string): Message {
  return new Message(message.body, {
    TransLastIdxSigGroups: message.attachments.TransLastIdxSigGroups.map((group) => ({ ...group, prefix })),
    TransIdxSigGroups: message.attachments.TransIdxSigGroups.map((group) => ({ ...group, prefix })),
  });
}

function roleReply(controller: Controller, witness: Witness, dt: Date) {
  const message = RoutedEvent.reply({
    dt,
    r: "/end/role/add",
    a: { cid: controller.aid, role: "mailbox", eid: witness.aid },
  });
  return endorse(message, { signers: [controller.signer], state: controller.state, latest: true });
}

describe(basename(import.meta.url), () => {
  test("should have a stable AID after construction", async () => {
    const w1 = makeWitness();
    const w2 = makeWitness(); // same seed → same key → same AID
    assert.strictEqual(w1.aid, w2.aid);
    assert(w1.aid.length > 0);
  });

  // A peer joins this URL with a path, so a trailing slash produces `//receipts`,
  // which matches no route — and the URL is signed into controller KELs, so the
  // mistake outlives the deployment that made it.
  test("should strip a trailing slash from the published location", async () => {
    const witness = new Witness({
      privateKey: generateKeyPair({ insecureSeed: "test-witness" }).privateKey,
      url: "https://witness.example.com/",
      store: new MemoryStore(),
    });

    const location = witness.location[0];
    assert.strictEqual((location.body.a as { url: string }).url, "https://witness.example.com");
  });

  describe("receipt()", () => {
    test("should endorse a valid event and return a receipt", async () => {
      const witness = makeWitness();
      const msg = makeController([witness.aid]).message;

      const receipt = await witness.receipt(msg);

      assert.strictEqual(receipt.body.t, "rct");
      assert.strictEqual(receipt.body.i, msg.body.i);
      assert.strictEqual(receipt.attachments.NonTransReceiptCouples[0].prefix, witness.aid);

      const wig = receipt.attachments.NonTransReceiptCouples[0].sig;

      assert(verifySignature(msg.raw, witness.aid, wig).ok);
    });

    test("should reject when witness is not a backer for the AID", async () => {
      const witness = makeWitness();
      const msg = makeController().message; // no witnesses listed

      await assert.rejects(() => witness.receipt(msg), WitnessError);
      assert.strictEqual((await Array.fromAsync(witness.getKeyEvents(msg.body.i))).length, 0);
    });

    test("should reject when no controller signatures are present", async () => {
      const witness = makeWitness();
      const msg = new Message(makeController().message.body, { ControllerIdxSigs: [] });

      await assert.rejects(() => witness.receipt(msg), WitnessError);
    });

    test("should store the event so getKeyEvents returns it", async () => {
      const witness = makeWitness();
      const msg = makeController([witness.aid]).message;

      await witness.receipt(msg);

      const stored = await Array.fromAsync(witness.getKeyEvents(msg.body.i));
      assert.strictEqual(stored.length, 1);
      assert.strictEqual(stored[0].body.t, "icp");
    });

    test("should reject when icp controller signature is invalid", async () => {
      const witness = makeWitness();
      const { publicKey: controllerPub } = generateKeyPair();
      const icp = KeyEvent.incept({ signingKeys: [controllerPub], nextKeyDigests: [] });

      const wrongKey = generateKeyPair().privateKey;
      const badSig = signRaw(icp.raw, wrongKey, 0);
      const msg = new Message(icp.body, { ControllerIdxSigs: [badSig] });

      await assert.rejects(() => witness.receipt(msg), WitnessError);
    });

    test("should reject when ixn controller signature is invalid", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      const state = KeyEventLog.from(await Array.fromAsync(witness.getKeyEvents(controller.aid))).state;
      const ixn = KeyEvent.interact(state);

      const wrongKey = generateKeyPair().privateKey;
      const badSig = signRaw(ixn.raw, wrongKey, 0);
      const msg = new Message(ixn.body, { ControllerIdxSigs: [badSig] });

      await assert.rejects(() => witness.receipt(msg), WitnessError);
    });
  });

  describe("getKeyEvents()", () => {
    test("should return empty for unknown AID", async () => {
      const witness = makeWitness();
      const stored = await Array.fromAsync(witness.getKeyEvents("unknown-aid"));
      assert.strictEqual(stored.length, 0);
    });
  });

  describe("rct", () => {
    test("should be a no-op for non-rct events", async () => {
      const witness = makeWitness();
      const icp = makeController().message;

      await witness.handleMessage(icp);

      const stored = await Array.fromAsync(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(stored.length, 0);
    });

    test("should be a no-op for rct when no event is stored for that AID", async () => {
      const witness = makeWitness();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        insecureSeed: "other-witness",
        nonTransferable: true,
      });

      const icp = makeController([otherPub]).message;
      const rctMsg = receiptFrom(icp, { privateKey: otherKey, publicKey: otherPub });

      await witness.handleMessage(rctMsg);

      const stored = await Array.fromAsync(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(stored.length, 0);
    });

    test("should be a no-op for rct when witness is not in the AID's backer list", async () => {
      const store = new MemoryStore();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        insecureSeed: "other-witness",
        nonTransferable: true,
      });
      const controller = makeController([otherPub]);
      await new WitnessStorage(store).saveEvent(controller.message, new Date());

      const witness = makeWitness(store);
      const saveSpy = mock.method(store, "put");

      const icp = controller.message;
      const rctMsg = receiptFrom(icp, { privateKey: otherKey, publicKey: otherPub });

      await witness.handleMessage(rctMsg);

      assert.strictEqual(saveSpy.mock.callCount(), 0);
    });

    test("should merge NonTransReceiptCouples from another witness", async () => {
      const witness = makeWitness();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        insecureSeed: "other-witness",
        nonTransferable: true,
      });

      const icp = makeController([witness.aid, otherPub]).message;
      await witness.receipt(icp);

      const before = await Array.fromAsync(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(before[0]?.attachments.WitnessIdxSigs.length, 1);

      const rctMsg = receiptFrom(icp, { privateKey: otherKey, publicKey: otherPub });

      await witness.handleMessage(rctMsg);

      const after = await Array.fromAsync(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(after[0]?.attachments.WitnessIdxSigs.length, 2);
    });
  });

  describe("exn /fwd", () => {
    test("should store the embedded message under the named recipient and topic", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);
      const inner = payload();

      await witness.handleMessage(forwardTo(controller.aid, "/credential", inner));

      const replies = await witness.handleMessage(pollFor(controller, witness.aid, { "/credential": 0 }));
      assert.strictEqual(replies.length, 1);
      assert.strictEqual(replies[0].id, 0);
      assert.strictEqual(replies[0].topic, "/credential");
      assert.strictEqual(replies[0].message.body.d, inner.body.d);
    });

    test("should allocate dense ordinals from zero per topic", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      for (let i = 0; i < 3; i++) {
        await witness.handleMessage(forwardTo(controller.aid, "/credential", payload()));
      }
      await witness.handleMessage(forwardTo(controller.aid, "/challenge", payload()));

      const credential = await witness.handleMessage(pollFor(controller, witness.aid, { "/credential": 0 }));
      assert.deepStrictEqual(
        credential.map((reply) => reply.id),
        [0, 1, 2],
      );

      const challenge = await witness.handleMessage(pollFor(controller, witness.aid, { "/challenge": 0 }));
      assert.deepStrictEqual(
        challenge.map((reply) => reply.id),
        [0],
      );
    });

    test("should accept a bare topic and answer a slashed one, the way KERIpy spells them", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      await witness.handleMessage(forwardTo(controller.aid, "credential", payload()));

      const replies = await witness.handleMessage(pollFor(controller, witness.aid, { "/credential": 0 }));
      assert.strictEqual(replies.length, 1);
      assert.strictEqual(replies[0].topic, "/credential");
    });

    // A stranger's poll is refused too, so the store is the only place that can
    // show the deposit never landed.
    test("should refuse a deposit for an AID the witness does not back", async () => {
      const store = new MemoryStore();
      const witness = makeWitness(store);
      const stranger = makeController(); // never receipted, so never backed

      await witness.handleMessage(forwardTo(stranger.aid, "/credential", payload()));

      const stored = new WitnessStorage(store).getMailboxEntries(stranger.aid, "credential", 0);
      assert.strictEqual((await Array.fromAsync(stored)).length, 0);
    });

    test("should refuse a topic KERIpy does not define", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      await witness.handleMessage(forwardTo(controller.aid, "/nonce-8f21c3", payload()));

      const replies = await witness.handleMessage(pollFor(controller, witness.aid, { "/nonce-8f21c3": 0 }));
      assert.deepStrictEqual(replies, [], "each accepted topic is its own retention budget");
    });
  });

  describe("qry mbx", () => {
    test("should return entries from the inclusive offset", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      for (let i = 0; i < 4; i++) {
        await witness.handleMessage(forwardTo(controller.aid, "/credential", payload()));
      }

      const replies = await witness.handleMessage(pollFor(controller, witness.aid, { "/credential": 2 }));
      assert.deepStrictEqual(
        replies.map((reply) => reply.id),
        [2, 3],
      );
    });

    test("should refuse an unsigned query", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);
      await witness.handleMessage(forwardTo(controller.aid, "/credential", payload()));

      const unsigned = RoutedEvent.query({
        r: "mbx",
        q: { src: witness.aid, i: controller.aid, topics: { "/credential": 0 } },
      });

      assert.deepStrictEqual(await witness.handleMessage(unsigned), []);
    });

    test("should refuse a query signed by anyone but the mailbox owner", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);
      const eavesdropper = await backedBy(witness);
      await witness.handleMessage(forwardTo(controller.aid, "/credential", payload()));

      const stolen = pollFor(controller, witness.aid, { "/credential": 0 }, eavesdropper);

      assert.deepStrictEqual(await witness.handleMessage(stolen), []);
    });

    test("should refuse a query signed by someone else but claiming the owner's prefix", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);
      const eavesdropper = await backedBy(witness);
      await witness.handleMessage(forwardTo(controller.aid, "/credential", payload()));

      const stolen = pollFor(controller, witness.aid, { "/credential": 0 }, eavesdropper);
      const forged = claimPrefix(stolen, controller.aid);

      assert.deepStrictEqual(await witness.handleMessage(forged), [], "the prefix on the group is a claim, not proof");
    });

    test("should refuse a query for an AID the witness does not back", async () => {
      const witness = makeWitness();
      const stranger = makeController();

      const replies = await witness.handleMessage(pollFor(stranger, witness.aid, { "/credential": 0 }));

      assert.deepStrictEqual(replies, []);
    });
  });

  describe("rpy /end/role/add", () => {
    test("should keep only the newest registration", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      const first = roleReply(controller, witness, new Date("2026-01-01T00:00:00Z"));
      const second = roleReply(controller, witness, new Date("2026-02-01T00:00:00Z"));
      await witness.handleMessage(first);
      await witness.handleMessage(second);

      assert.strictEqual((await witness.mailboxRole(controller.aid))?.body.d, second.body.d);
    });

    test("should not let a replayed older registration displace the current one", async () => {
      const witness = makeWitness();
      const controller = await backedBy(witness);

      const older = roleReply(controller, witness, new Date("2026-01-01T00:00:00Z"));
      const newer = roleReply(controller, witness, new Date("2026-02-01T00:00:00Z"));
      await witness.handleMessage(newer);
      await witness.handleMessage(older);

      assert.strictEqual((await witness.mailboxRole(controller.aid))?.body.d, newer.body.d);
    });
  });
});
