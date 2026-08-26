import assert from "node:assert";
import { Buffer } from "node:buffer";
import path from "node:path";
import test, { describe } from "node:test";
import fixture from "../fixtures/events/keri-1.3.6.json" with { type: "json" };
import { encodeText, type Message } from "../src/cesr/main.ts";
import { decodeUtf8 } from "../src/encoding/main.ts";
import {
  ed25519Signer,
  type InceptArgs,
  type InteractArgs,
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  type KeyState,
  parse,
  type RotateArgs,
  signEvent,
} from "../src/main.ts";

const fixtures = [fixture];

type Fixture = typeof fixture;
type Case = Fixture["events"][number];

function build(entry: Case, state: KeyState | null): Message<KeyEventBody> {
  switch (entry.sad.t) {
    case "icp":
      return KeyEvent.incept(entry.args as InceptArgs);
    case "ixn":
      return KeyEvent.interact(state as KeyState, entry.args as InteractArgs);
    case "rot":
      return KeyEvent.rotate(state as KeyState, entry.args as RotateArgs);
    default:
      throw new Error(`Unhandled event type ${entry.sad.t}`);
  }
}

/** `vn`, `f` and `et` have no keri-js counterpart; `ee.br`/`ee.ba` are folded into `backers`. */
function expectedState(state: Fixture["kel"]["state"]): KeyState {
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
 * Each event is built from the state its predecessors settled, so one failure blocks the rest —
 * they report that instead of a stale diff.
 */
function rebuild(events: readonly Case[]) {
  const results: { entry: Case; message?: Message<KeyEventBody>; error?: unknown }[] = [];
  let log = KeyEventLog.empty();
  let state: KeyState | null = null;
  let blocked: string | null = null;

  for (const entry of events) {
    if (blocked) {
      results.push({ entry, error: new Error(`not reached: ${blocked} failed earlier in the KEL`) });
      continue;
    }

    try {
      const signers = entry.seeds.map((seed) => ed25519Signer(Uint8Array.from(Buffer.from(seed, "hex"))));
      const message = build(entry, state);
      signEvent(message, { signers, state: state ?? undefined });

      // `append` verifies the signatures, so the chain also checks that what we built parses back.
      log = log.append(message);
      state = log.state;
      results.push({ entry, message });
    } catch (error) {
      blocked = entry.name;
      results.push({ entry, error });
    }
  }

  return results;
}

function serialize(message: Message): string {
  return decodeUtf8(message.raw) + encodeText(message.attachments.frames());
}

/** `strictEqual` would print a few thousand characters twice and leave you to spot the difference. */
function assertSameStream(actual: string, expected: string): void {
  if (actual === expected) {
    return;
  }

  let at = 0;
  while (at < actual.length && at < expected.length && actual[at] === expected[at]) {
    at++;
  }

  const from = Math.max(0, at - 60);
  const excerpt = (stream: string) => `${from > 0 ? "…" : ""}${stream.slice(from, at + 60)}…`;

  assert.fail(
    `KEL streams diverge at offset ${at} (expected ${expected.length} characters, got ${actual.length})\n` +
      `  expected: ${excerpt(expected)}\n` +
      `  actual:   ${excerpt(actual)}`,
  );
}

describe(path.parse(import.meta.url).base, () => {
  for (const { keripy, events, kel } of fixtures) {
    describe(`keripy ${keripy}`, () => {
      const rebuilt = rebuild(events);

      describe("events", () => {
        for (const entry of events) {
          test(`reads ${entry.name}`, async () => {
            const messages = await Array.fromAsync(parse(entry.stream));

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

            // The body is checked above, so comparing only the attachment tail keeps a signature
            // mismatch down to one short line.
            assert.strictEqual(
              encodeText(message.attachments.frames()),
              entry.stream.slice(entry.raw.length),
              "attachments",
            );
          });
        }
      });

      describe("key event log", () => {
        test("rebuilds the same KEL from the same seeds", () => {
          const failed = rebuilt.find(({ error }) => error);
          if (failed) {
            throw failed.error;
          }

          assertSameStream(rebuilt.map(({ message }) => serialize(message as Message)).join(""), kel.stream);
        });

        test("settles the same key state", async () => {
          const log = await KeyEventLog.parse(kel.stream);

          assert.deepStrictEqual(log.state, expectedState(kel.state));
        });
      });
    });
  }
});
