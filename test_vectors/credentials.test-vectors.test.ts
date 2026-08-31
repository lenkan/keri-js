import assert from "node:assert";
import { Buffer } from "node:buffer";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test, { describe } from "node:test";
import {
  Attachments,
  decodeUtf8,
  encodeText,
  encodeUtf8,
  type Frame,
  Indexer,
  type Message,
  parse,
} from "../src/cesr/main.ts";
import {
  Credential,
  type CredentialArgs,
  collect,
  ed25519Signer,
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  Registry,
  type Signer,
  signEvent,
  verify,
} from "../src/main.ts";

interface Key {
  seed: string;
  public: string;
}

interface Case {
  name: string;
  sad: Record<string, unknown> & { t?: string };
  raw: string;
  attachments: string;
}

interface Log {
  keripy: string;
  name: string;
  version: string;
  controllers: Key[];
  events: Case[];
  states: Record<string, { s: string; d: string }>;
}

const FIXTURES = new URL("../fixtures/credentials/", import.meta.url);

/** The recorded events, and beside them the stream a `kli vc export --full` of the same log emits. */
interface Fixture {
  log: Log;
  stream: string;
}

function load(): Fixture[] {
  const fixtures: Fixture[] = [];

  for (const version of readdirSync(FIXTURES).sort()) {
    const directory = new URL(`${version}/`, FIXTURES);
    for (const file of readdirSync(directory).sort()) {
      if (file.endsWith(".json")) {
        const log: Log = JSON.parse(readFileSync(new URL(file, directory), "utf8"));
        fixtures.push({ log, stream: readFileSync(new URL(`${log.name}.cesr`, directory), "utf8") });
      }
    }
  }

  if (fixtures.length === 0) {
    throw new Error(`No credential vectors under ${FIXTURES.pathname} — run scripts/generate-credential-vectors.py`);
  }

  return fixtures;
}

function message(entry: Case): string {
  return entry.raw + entry.attachments;
}

function signerFor(key: Key): Signer {
  const raw = Uint8Array.from(Buffer.from(key.seed, "hex"));

  for (const signer of [ed25519Signer(raw), ed25519Signer(raw, { nonTransferable: true })]) {
    if (signer.publicKey === key.public) {
      return signer;
    }
  }

  return assert.fail(`the seed listed for ${key.public} derives neither form of that key`);
}

/** Which keys signed, read off the indices the attached signatures carry. */
function signers(entry: Case, keys: string[], available: ReadonlyMap<string, Signer>): Signer[] {
  const attachments = Attachments.parse(encodeUtf8(entry.attachments));
  assert.ok(attachments, `${entry.name} has no attachments`);

  return attachments.ControllerIdxSigs.map((sig) => {
    const key = keys[Indexer.parse(sig).index];
    const signer = available.get(key);
    assert.ok(signer, `${entry.name} is signed by ${key}, which the log declares no seed for`);
    return signer;
  });
}

/** A section is rebuilt from its contents; its `d` is what the constructor recomputes. */
function section(block: unknown): Record<string, unknown> {
  const { d: _, ...rest } = block as Record<string, unknown>;
  return rest;
}

/**
 * The event in `issuer`'s KEL whose `a` anchors `sad` — found by scanning for the seal rather than
 * read off the fixture's own `SealSourceCouple`, so the couple this rebuild emits has to be earned.
 */
function anchoringEvent(sad: Record<string, unknown>, issuer: KeyEventLog): Message<KeyEventBody> {
  const seal = { i: sad.i, s: sad.s, d: sad.d };

  for (const event of issuer.events) {
    const anchors = (event.body.a ?? []) as Record<string, unknown>[];
    if (anchors.some((anchor) => anchor.i === seal.i && anchor.s === seal.s && anchor.d === seal.d)) {
      return event;
    }
  }

  return assert.fail(`no event in ${issuer.state.identifier} anchors ${sad.t} ${String(sad.d)}`);
}

interface Rebuilt {
  entry: Case;
  message?: Message;
  error?: unknown;
}

function rebuild(log: Log): Rebuilt[] {
  const available = new Map(log.controllers.map((key) => [key.public, signerFor(key)]));
  const kels = new Map<string, KeyEventLog>();
  const issuance = new Map<string, Case>();
  const results: Rebuilt[] = [];

  // Which AID owns a registry, so an `iss` can find the KEL its anchor lives in. The `vcp` names it.
  const registryIssuer = new Map<string, string>();
  for (const entry of log.events) {
    if (entry.sad.t === "vcp") {
      registryIssuer.set(entry.sad.i as string, entry.sad.ii as string);
    }
    if (entry.sad.t === "iss") {
      issuance.set(entry.sad.i as string, entry);
    }
  }

  for (const entry of log.events) {
    try {
      results.push({ entry, message: build(entry, kels, registryIssuer, issuance, available) });
    } catch (error) {
      results.push({ entry, error });
    }
  }

  return results;
}

function build(
  entry: Case,
  kels: Map<string, KeyEventLog>,
  registryIssuer: Map<string, string>,
  issuance: Map<string, Case>,
  available: ReadonlyMap<string, Signer>,
): Message {
  const sad = entry.sad;

  switch (sad.t) {
    case "icp": {
      const event = KeyEvent.incept({
        signingKeys: sad.k as string[],
        signingThreshold: sad.kt as string,
        nextKeyDigests: sad.n as string[],
        nextThreshold: sad.nt as string,
        backers: sad.b as string[],
        backerThreshold: Number.parseInt(sad.bt as string, 16),
        configTraits: sad.c as string[],
      });

      signEvent(event, { signers: signers(entry, sad.k as string[], available) });
      kels.set(sad.i as string, KeyEventLog.empty().append(event));
      return event;
    }

    case "ixn": {
      const kel = kels.get(sad.i as string);
      assert.ok(kel, `${entry.name} extends ${String(sad.i)}, which has no inception yet`);

      const data = (sad.a as Record<string, unknown>[])[0];
      const event = KeyEvent.interact(kel.state, data ? { data } : {});

      signEvent(event, { signers: signers(entry, kel.state.signingKeys, available), state: kel.state });
      kels.set(sad.i as string, kel.append(event));
      return event;
    }

    case "vcp": {
      const event = Registry.incept({ ii: sad.ii as string, n: sad.n as string });
      const issuer = kels.get(sad.ii as string);
      assert.ok(issuer, `${entry.name} is anchored in ${String(sad.ii)}, which has no KEL yet`);

      KeyEvent.attachSourceSeal(event, anchoringEvent(sad, issuer));
      return event;
    }

    case "iss": {
      const event = Registry.issue({ i: sad.i as string, ri: sad.ri as string, dt: sad.dt as string });
      const owner = registryIssuer.get(sad.ri as string);
      assert.ok(owner, `${entry.name} names registry ${String(sad.ri)}, which the log has no vcp for`);
      const issuer = kels.get(owner);
      assert.ok(issuer, `${entry.name} is anchored in ${owner}, which has no KEL yet`);

      KeyEvent.attachSourceSeal(event, anchoringEvent(sad, issuer));
      return event;
    }

    default: {
      assert.ok(sad.v && String(sad.v).startsWith("ACDC"), `Unhandled event type ${String(sad.t)}`);

      const credential = Credential.create({
        ...(sad.u ? { u: sad.u as string } : {}),
        i: sad.i as string,
        ri: sad.ri as string,
        s: sad.s as string,
        a: section(sad.a) as CredentialArgs["a"],
        ...(sad.e ? { e: section(sad.e) } : {}),
        r: section(sad.r),
      });

      // `keri.app.signing.serialize` — the credential's own TEL, at the issuance event.
      const iss = issuance.get(sad.d as string);
      assert.ok(iss, `${entry.name} has no iss event in the log`);
      credential.attachments.SealSourceTriples.push({
        prefix: sad.d as string,
        snu: iss.sad.s as string,
        digest: iss.sad.d as string,
      });

      return credential;
    }
  }
}

/**
 * keripy pipelines a message's attachments but not a credential's proof: `messagize` opens an
 * attachment group, `keri.app.signing.serialize` writes the seal bare. keri-js always pipelines,
 * which is valid CESR and what keripy's own parser accepts, so for an ACDC the byte claim is over
 * the groups inside the wrapper rather than the wrapper itself.
 */
function attachmentFrames(entry: Case, message: Message): Frame[] {
  const frames = message.attachments.frames();
  return isCredential(entry) ? frames.slice(1) : frames;
}

function isCredential(entry: Case): boolean {
  return String(entry.sad.v).startsWith("ACDC");
}

function serialize(entry: Case, message: Message): string {
  return decodeUtf8(message.raw) + encodeText(attachmentFrames(entry, message));
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
    `streams diverge at offset ${at} (expected ${expected.length} characters, got ${actual.length})\n` +
      `  expected: ${excerpt(expected)}\n` +
      `  actual:   ${excerpt(actual)}`,
  );
}

const byVersion = Map.groupBy(load(), (fixture) => fixture.log.keripy);

describe(path.parse(import.meta.url).base, () => {
  for (const [keripy, fixtures] of byVersion) {
    describe(`keripy ${keripy}`, () => {
      for (const { log, stream } of fixtures) {
        describe(log.name, () => {
          const rebuilt = rebuild(log);

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
              assert.strictEqual(encodeText(attachmentFrames(entry, message)), entry.attachments, "attachments");
            });
          }

          // The two files are one fixture, so a stale pair is a failure rather than a puzzle.
          test("exports the events it records", () => {
            assertSameStream(log.events.map(message).join(""), stream);
          });

          test("rebuilds the same stream from the same seeds", () => {
            const failed = rebuilt.find(({ error }) => error);
            if (failed) {
              throw failed.error;
            }

            assertSameStream(
              rebuilt.map(({ entry, message }) => serialize(entry, message as Message)).join(""),
              stream,
            );
          });

          test("settles the same key state", async () => {
            for (const [identifier, expected] of Object.entries(log.states)) {
              const kel = KeyEventLog.fromMessages(
                (await Array.fromAsync(parse(stream)))
                  .filter((candidate) => KeyEvent.isKeyEvent(candidate) && candidate.body.i === identifier)
                  .map((candidate) => candidate as Message<KeyEventBody>),
              );

              assert.strictEqual(kel.state.lastEvent.s, expected.s, identifier);
              assert.strictEqual(kel.state.lastEvent.d, expected.d, identifier);
            }
          });

          // The claim the whole fixture exists to make: KERIpy's own bytes, read end to end, produce
          // a verified chain — every check passing and the edge resolving to the credential it names.
          test("verifies the chain KERIpy issued", async () => {
            const report = verify(await collect(stream));

            assert.deepStrictEqual(report.problems, []);
            assert.strictEqual(report.credentials.length, 2);

            for (const credential of report.credentials) {
              assert.ok(credential.ok, `${credential.said} did not verify`);
              assert.strictEqual(credential.status, "issued");
            }

            const chained = report.credentials.find((candidate) => candidate.edges.length > 0);
            assert.ok(chained, "no credential in the fixture carries an edge");

            const [edge] = chained.edges;
            assert.strictEqual(edge.label, "qvi");
            assert.ok(edge.ok, `edge ${edge.label} -> ${edge.said} did not resolve`);
            assert.ok(
              report.credentials.some((candidate) => candidate.said === edge.said),
              `${edge.said} is not one of the credentials in the stream`,
            );
          });
        });
      }
    });
  }
});
