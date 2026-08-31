import assert from "node:assert";
import path from "node:path";
import test, { describe } from "node:test";
import { decodeUtf8, encodeText, Indexer, Message, parse } from "../src/cesr/main.ts";
import {
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  type KeyState,
  type ReceiptEventBody,
  type Signer,
  signEvent,
  type Threshold,
} from "../src/main.ts";
import {
  anchoringEvent,
  assertSameStream,
  attachmentsOf,
  type Log as BaseLog,
  type Case,
  type Key,
  load,
  message,
  signerRegistry,
  signers,
} from "./support/keripy.ts";

/** KERIpy's `KeyStateRecord`, minus the first-seen `dt` the generator drops as non-deterministic. */
interface KeyStateRecord {
  i: string;
  s: string;
  d: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  b: string[];
  c: string[];
  di: string;
  ee: { s: string; d: string };
}

interface Log extends BaseLog {
  backers: Key[];
  state: KeyStateRecord;
}

/** The wire fields the constructors take their arguments from. `ixn` carries none of them. */
type Establishment = {
  k: string[];
  kt: Threshold;
  n: string[];
  nt: Threshold;
  bt: string;
  b?: string[];
  br?: string[];
  ba?: string[];
  c?: string[];
  di?: string;
};

/**
 * Which backers receipted, read off the same wire the controller indices come from. A couple names
 * its signer by prefix and an indexed signature by position, so both resolve against `backers`.
 */
function receiptors(entry: Case, backers: string[], available: ReadonlyMap<string, Signer>): Signer[] {
  const attachments = attachmentsOf(entry);
  const keys = [
    ...attachments.WitnessIdxSigs.map((sig) => backers[Indexer.parse(sig).index]),
    ...attachments.NonTransReceiptCouples.map((couple) => couple.prefix),
  ];

  return keys.map((key) => {
    const signer = available.get(key);
    assert.ok(signer, `${entry.name} is receipted by ${key}, which the log declares no seed for`);
    return signer;
  });
}

function build(entry: Case, state: KeyState | null): Message<KeyEventBody> {
  const sad = entry.sad as unknown as Establishment;

  const inception = {
    signingKeys: sad.k,
    signingThreshold: sad.kt,
    nextKeyDigests: sad.n,
    nextThreshold: sad.nt,
    backers: sad.b,
    backerThreshold: Number.parseInt(sad.bt, 16),
    configTraits: sad.c,
  };

  const rotation = {
    signingKeys: sad.k,
    signingThreshold: sad.kt,
    nextKeyDigests: sad.n,
    nextThreshold: sad.nt,
    removeBackers: sad.br,
    addBackers: sad.ba,
    backerThreshold: Number.parseInt(sad.bt, 16),
  };

  switch (entry.sad.t) {
    case "icp":
      return KeyEvent.incept(inception);
    case "dip":
      return KeyEvent.delegatedIncept({ ...inception, delegator: sad.di as string });
    case "ixn": {
      const data = (entry.sad as { a?: Record<string, unknown>[] }).a?.[0];
      return KeyEvent.interact(state as KeyState, data ? { data } : {});
    }
    case "rot":
      return KeyEvent.rotate(state as KeyState, rotation);
    case "drt":
      return KeyEvent.delegatedRotate(state as KeyState, rotation);
    default:
      throw new Error(`Unhandled event type ${entry.sad.t}`);
  }
}

/** `vn`, `f` and `et` have no keri-js counterpart; `ee.br`/`ee.ba` are folded into `backers`. */
function expectedState(state: KeyStateRecord): KeyState {
  return {
    identifier: state.i,
    signingThreshold: state.kt,
    signingKeys: state.k,
    nextThreshold: state.nt,
    nextKeyDigests: state.n,
    backerThreshold: state.bt,
    backers: state.b,
    configTraits: state.c,
    // KERIpy writes "" for an undelegated AID; keri-js leaves the key present and undefined.
    delegator: state.di || undefined,
    lastEvent: { i: state.i, s: state.s, d: state.d },
    lastEstablishment: { i: state.i, s: state.ee.s, d: state.ee.d },
  };
}

/**
 * Each event is built from the state its own identifier's predecessors settled, so one failure
 * blocks the rest of that identifier — they report that instead of a stale diff. A delegated log
 * carries two identifiers, and a broken delegate must not be reported as a diff on the delegator.
 *
 * A backered event is receipted the way the protocol does it: every backer the fixture says signed
 * issues a receipt, and the receipts are folded back onto the event. Nothing fabricates a witness
 * signature directly, because nothing in KERI does.
 */
function rebuild(log: Log) {
  const available = signerRegistry([...log.controllers, ...log.backers]);

  const results: { entry: Case; message?: Message; error?: unknown }[] = [];
  const logs = new Map<string, KeyEventLog>();
  const blocked = new Map<string, string>();
  const built = new Map<string, { message: Message<KeyEventBody>; backers: string[] }>();

  for (const entry of log.events) {
    const identifier = entry.sad.i as string;
    const stalled = blocked.get(identifier);
    if (stalled) {
      results.push({ entry, error: new Error(`not reached: ${stalled} failed earlier in the KEL`) });
      continue;
    }

    try {
      const events = logs.get(identifier) ?? KeyEventLog.empty();
      const state = events.events.length > 0 ? events.state : null;

      // A receipt is not a KEL event, so it is rebuilt from the event it receipts and never appended.
      if (entry.sad.t === "rct") {
        const target = built.get(entry.sad.d as string);
        assert.ok(target, `${entry.name} receipts ${entry.sad.d}, which the log does not carry`);
        const { backers } = target;
        // Whether a backer receipted as a witness or in the generic form is a caller's choice in
        // both implementations — `Hab.witness` against `Hab.receipt` — so it is read off the wire,
        // the same way which keys signed is.
        const asWitness = attachmentsOf(entry).WitnessIdxSigs.length > 0;
        results.push({
          entry,
          message: KeyEvent.receipt(target.message, {
            signers: receiptors(entry, backers, available),
            backers: asWitness ? backers : [],
          }),
        });
        continue;
      }

      const message = build(entry, state);
      const keys = (entry.sad as unknown as Establishment).k ?? (state as KeyState).signingKeys;
      signEvent(message, { signers: signers(entry, keys, available), state: state ?? undefined });

      let delegator: KeyEventLog | undefined;
      if (message.body.t === "dip" || message.body.t === "drt") {
        const delegatorAid = message.body.t === "dip" ? (entry.sad.di as string) : (state as KeyState).delegator;
        delegator = logs.get(delegatorAid as string);
        assert.ok(delegator, `${entry.name} is delegated by ${delegatorAid}, which the log does not carry`);
        const anchored = `${message.body.t} ${message.body.d}`;
        KeyEvent.attachSourceSeal(message, anchoringEvent(KeyEvent.keyEventSeal(message), delegator, anchored));
      }

      const backers = KeyEvent.backersFor(message, state);
      const witnesses = receiptors(entry, backers, available);
      if (witnesses.length > 0) {
        KeyEvent.applyReceipt(message, KeyEvent.receipt(message, { signers: witnesses, backers }), backers);
      }

      // `append` verifies the signatures — controller and witness both — and, for a delegated
      // event, the anchor, so the chain also checks that what we built parses back.
      logs.set(identifier, events.append(message, { delegator }));
      built.set(message.body.d, { message, backers });
      results.push({ entry, message });
    } catch (error) {
      blocked.set(identifier, entry.name);
      results.push({ entry, error });
    }
  }

  return results;
}

function serialize(message: Message): string {
  return decodeUtf8(message.raw) + encodeText(message.attachments.frames());
}

const byVersion = Map.groupBy(load<Log>("events", "generate-event-vectors.py"), ({ log }) => log.keripy);

describe(path.parse(import.meta.url).base, () => {
  for (const [keripy, fixtures] of byVersion) {
    describe(`keripy ${keripy}`, () => {
      for (const { log } of fixtures) {
        describe(log.name, () => {
          const rebuilt = rebuild(log);
          const stream = log.events.map(message).join("");

          for (const entry of log.events) {
            test(`reads ${entry.name}`, async () => {
              const messages = await Array.fromAsync(parse(message(entry)));

              assert.strictEqual(messages.length, 1);
              assert.deepStrictEqual(messages[0].body, entry.sad);
            });
          }

          for (const { entry, message, error } of rebuilt) {
            test(`writes ${entry.name}`, () => {
              if (error || !message) {
                throw error;
              }

              // Bodies first: a field-level diff names the culprit where two 400-character JSON
              // strings do not. The byte comparison is the real claim — it also pins field order.
              assert.deepStrictEqual(message.body, entry.sad, "event body");
              assert.strictEqual(decodeUtf8(message.raw), entry.raw, "serialized body");
              assert.strictEqual(encodeText(message.attachments.frames()), entry.attachments, "attachments");
            });
          }

          test("rebuilds the same KEL from the same seeds", () => {
            const failed = rebuilt.find(({ error }) => error);
            if (failed) {
              throw failed.error;
            }

            assertSameStream(
              rebuilt.map(({ message }) => serialize(message as Message)).join(""),
              stream,
              "KEL streams",
            );
          });

          // Against KERIpy's own bytes on both sides, so it holds whether or not the rebuild works:
          // a couple naming a backer has to promote to the very signature the event already carries.
          for (const entry of log.events.filter((candidate) => candidate.sad.t === "rct")) {
            test(`applies ${entry.name} to the event it receipts`, async () => {
              const target = log.events.find(
                (candidate) => candidate.sad.t !== "rct" && candidate.sad.d === entry.sad.d,
              );
              assert.ok(target, `${entry.name} receipts ${entry.sad.d}, which the log does not carry`);

              const [receipt] = await Array.fromAsync(parse(message(entry)));
              const [event] = await Array.fromAsync(parse(message(target)));

              const backers = KeyEvent.backersFor(event as Message<KeyEventBody>, null);
              const applied = KeyEvent.applyReceipt(
                new Message(event.body as KeyEventBody),
                receipt as Message<ReceiptEventBody>,
                backers,
              );

              assert.ok(applied.attachments.WitnessIdxSigs.length > 0, "no witness signature came out of the receipt");
              for (const sig of applied.attachments.WitnessIdxSigs) {
                assert.ok(
                  event.attachments.WitnessIdxSigs.includes(sig),
                  `${sig} is not one of the witness signatures ${target.name} carries`,
                );
              }
            });
          }

          // No `allowPartiallyWitnessed` here: the fixture carries KERIpy's own witness signatures,
          // so a backered log has to clear its own backer threshold to settle.
          test("settles the same key state", async () => {
            const parsed = await KeyEventLog.parse(stream);

            assert.deepStrictEqual(parsed.state, expectedState(log.state));
          });
        });
      }
    });
  }
});
