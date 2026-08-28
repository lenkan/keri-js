import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { signWith as sign, signRaw } from "../../test_utils/signing.ts";
import { Message } from "../cesr/main.ts";
import { incept, KeyEventLog, type KeyState, rotate } from "../key-events/main.ts";
import { generateKeyPair, type KeyPair } from "../keys/main.ts";
import {
  CHALLENGE_RESPONSE_ROUTE,
  type ExchangeEventBody,
  exchange,
  type ReplyEventBody,
  reply,
} from "./routed-event.ts";
import { verifyExchange, verifyReply } from "./verification.ts";

const WORDS = ["abandon", "ability", "able", "about", "above", "absent"];

function inceptLog(keys: KeyPair[], nextKey: KeyPair, threshold?: string): KeyEventLog {
  const event = incept({
    signingKeys: keys.map((key) => key.publicKey),
    signingThreshold: threshold,
    nextKeyDigests: [nextKey.publicKeyDigest],
  });
  const sigs = sign(event, keys);
  return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
}

function rotateLog(log: KeyEventLog, newKey: KeyPair, nextKey: KeyPair): KeyEventLog {
  const event = rotate(log.state, { signingKeys: [newKey.publicKey], nextKeyDigests: [nextKey.publicKeyDigest] });
  return log.append(new Message(event.body, { ControllerIdxSigs: sign(event, [newKey]) }));
}

function challengeExn(
  state: KeyState,
  signers: KeyPair[],
  seal: { s: string; d: string } = state.lastEstablishment,
): Message<ExchangeEventBody> {
  const exn = exchange({
    sender: state.identifier,
    route: CHALLENGE_RESPONSE_ROUTE,
    anchor: { i: state.identifier, words: WORDS },
  });

  exn.attachments = {
    TransIdxSigGroups: [
      {
        prefix: state.identifier,
        snu: seal.s,
        digest: seal.d,
        ControllerIdxSigs: signers.map((key, index) => signRaw(exn.raw, key.privateKey, index)),
      },
    ],
  };

  return exn;
}

describe(basename(import.meta.url), () => {
  test("should accept a response signed with the current key", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);

    const result = verifyExchange(challengeExn(log.state, [key0]), log.state);
    assert.deepEqual(result, { ok: true });
  });

  test("should accept a response signed after a rotation", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const key2 = generateKeyPair();
    const log = rotateLog(inceptLog([key0], key1), key1, key2);

    const result = verifyExchange(challengeExn(log.state, [key1]), log.state);
    assert.deepEqual(result, { ok: true });
  });

  test("should reject a signature from the wrong key", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);

    const result = verifyExchange(challengeExn(log.state, [key1]), log.state);
    assert.equal(result.ok, false);
    assert.equal(result.kind, "invalid-signature");
  });

  test("should reject a seal naming a superseded establishment event", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const key2 = generateKeyPair();
    const before = inceptLog([key0], key1);
    const after = rotateLog(before, key1, key2);

    // The exact post-rotation replay: signed with the old key, sealed to the icp.
    const exn = challengeExn(after.state, [key0], before.state.lastEstablishment);
    const result = verifyExchange(exn, after.state);
    assert.equal(result.ok, false);
    assert.equal(result.kind, "stale-establishment");
  });

  test("should enforce the signing threshold", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const key2 = generateKeyPair();
    const log = inceptLog([key0, key1], key2, "2");

    const short = verifyExchange(challengeExn(log.state, [key0]), log.state);
    assert.equal(short.ok, false);
    assert.equal(short.kind, "invalid-signature");

    const full = verifyExchange(challengeExn(log.state, [key0, key1]), log.state);
    assert.deepEqual(full, { ok: true });
  });

  test("should reject a tampered body", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);

    const exn = challengeExn(log.state, [key0]);
    const tampered = new Message<ExchangeEventBody>(
      { ...exn.body, a: { i: log.state.identifier, words: [...WORDS, "extra"] } },
      exn.attachments,
    );

    const result = verifyExchange(tampered, log.state);
    assert.equal(result.ok, false);
    assert.equal(result.kind, "said-mismatch");
  });

  test("should reject a message without a signature group for the identifier", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);
    const other = inceptLog([key1], key0);

    const unsigned = exchange({
      sender: log.state.identifier,
      route: CHALLENGE_RESPONSE_ROUTE,
      anchor: { i: log.state.identifier, words: WORDS },
    });
    const missing = verifyExchange(unsigned, log.state);
    assert.equal(missing.ok, false);
    assert.equal(missing.kind, "no-signature");

    const foreign = verifyExchange(challengeExn(other.state, [key1]), log.state);
    assert.equal(foreign.ok, false);
    assert.equal(foreign.kind, "no-signature");
  });

  test("should accept a TransLastIdxSigGroup against the current keys", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);

    const exn = exchange({
      sender: log.state.identifier,
      route: CHALLENGE_RESPONSE_ROUTE,
      anchor: { i: log.state.identifier, words: WORDS },
    });
    exn.attachments = {
      TransLastIdxSigGroups: [
        { prefix: log.state.identifier, ControllerIdxSigs: [signRaw(exn.raw, key0.privateKey, 0)] },
      ],
    };

    assert.deepEqual(verifyExchange(exn, log.state), { ok: true });
  });

  test("should verify a signed rpy the same way", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);

    const rpy = reply({
      r: "/end/role/add",
      a: { cid: log.state.identifier, role: "mailbox", eid: "EMAILBOX" },
    });
    rpy.attachments = {
      TransIdxSigGroups: [
        {
          prefix: log.state.identifier,
          snu: log.state.lastEstablishment.s,
          digest: log.state.lastEstablishment.d,
          ControllerIdxSigs: [signRaw(rpy.raw, key0.privateKey, 0)],
        },
      ],
    };

    assert.deepEqual(verifyReply(rpy, log.state), { ok: true });

    const tampered = new Message<ReplyEventBody>(
      { ...rpy.body, a: { cid: log.state.identifier, role: "mailbox", eid: "EINTRUDER" } },
      rpy.attachments,
    );
    const result = verifyReply(tampered, log.state);
    assert.equal(result.ok, false);
    assert.equal(result.kind, "said-mismatch");
  });

  test("should compare seal sequence numbers numerically, not textually", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const log = inceptLog([key0], key1);

    // The attachments reader emits padded hex ("0a") while event `s` fields are
    // unpadded ("a") — fabricate a state at sn 10 to cover the normalization.
    const state: KeyState = { ...log.state, lastEstablishment: { ...log.state.lastEstablishment, s: "a" } };
    const exn = challengeExn(state, [key0], { s: "0a", d: state.lastEstablishment.d });

    assert.deepEqual(verifyExchange(exn, state), { ok: true });
  });
});
