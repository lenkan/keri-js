import assert from "node:assert";
import { Buffer } from "node:buffer";
import { readdirSync, readFileSync } from "node:fs";
import { Attachments, encodeUtf8, Indexer, type Message } from "../../src/cesr/main.ts";
import { ed25519Signer, type KeyEventBody, type KeyEventLog, type Signer } from "../../src/main.ts";

/** A seed and the one of its two derivable public keys that the log it belongs to uses. */
export interface Key {
  seed: string;
  public: string;
}

export interface Case {
  name: string;
  sad: Record<string, unknown> & { t?: string };
  raw: string;
  attachments: string;
}

/** What every generator writes. Each fixture adds the fields its own protocol settles. */
export interface Log {
  keripy: string;
  name: string;
  version: string;
  controllers: Key[];
  events: Case[];
}

/** The result of one rebuild attempt: a message, or the failure that stopped it. */
export interface Rebuilt {
  entry: Case;
  message?: Message;
  error?: unknown;
}

/**
 * One file per log, one directory per KERIpy version, so a new version is a directory to drop in.
 * `directory` comes back for the sibling files a fixture may carry beside its JSON.
 */
export function load<T extends Log>(folder: string, generator: string): { log: T; directory: URL }[] {
  const root = new URL(`../../fixtures/${folder}/`, import.meta.url);
  const fixtures: { log: T; directory: URL }[] = [];

  for (const version of readdirSync(root).sort()) {
    const directory = new URL(`${version}/`, root);
    for (const file of readdirSync(directory).sort()) {
      if (file.endsWith(".json")) {
        fixtures.push({ log: JSON.parse(readFileSync(new URL(file, directory), "utf8")), directory });
      }
    }
  }

  if (fixtures.length === 0) {
    throw new Error(`No vectors under ${root.pathname} — run scripts/${generator}`);
  }

  return fixtures;
}

export function message(entry: Case): string {
  return entry.raw + entry.attachments;
}

export function attachmentsOf(entry: Case): Attachments {
  const attachments = Attachments.parse(encodeUtf8(entry.attachments));
  assert.ok(attachments, `${entry.name} has no attachments`);
  return attachments;
}

/** Also checks the log's own claim: the seed has to derive the public key listed beside it. */
function signerFor(key: Key): Signer {
  const raw = Uint8Array.from(Buffer.from(key.seed, "hex"));

  for (const signer of [ed25519Signer(raw), ed25519Signer(raw, { nonTransferable: true })]) {
    if (signer.publicKey === key.public) {
      return signer;
    }
  }

  return assert.fail(`the seed listed for ${key.public} derives neither form of that key`);
}

export function signerRegistry(keys: Key[]): Map<string, Signer> {
  return new Map(keys.map((key) => [key.public, signerFor(key)]));
}

/**
 * Which keys signed, read off the indices the attached signatures carry. The fixture records no
 * signer list of its own — a 2-of-3 signed by keys 0 and 2 says so in its attachments.
 */
export function signers(entry: Case, keys: string[], available: ReadonlyMap<string, Signer>): Signer[] {
  return attachmentsOf(entry).ControllerIdxSigs.map((sig) => {
    const key = keys[Indexer.parse(sig).index];
    const signer = available.get(key);
    assert.ok(signer, `${entry.name} is signed by ${key}, which the log declares no seed for`);
    return signer;
  });
}

/**
 * The event in `kel` whose `a` carries `seal`. Callers derive the seal themselves rather than read
 * the fixture's own `SealSourceCouple`, which would assert nothing.
 */
export function anchoringEvent(
  seal: { i: string; s: string; d: string },
  kel: KeyEventLog,
  type: string,
): Message<KeyEventBody> {
  const event = kel.events.find((candidate) =>
    ((candidate.body.a ?? []) as Record<string, unknown>[]).some(
      (anchor) => anchor.i === seal.i && anchor.s === seal.s && anchor.d === seal.d,
    ),
  );

  assert.ok(event, `no event in ${kel.state.identifier} anchors ${type} ${seal.d}`);
  return event;
}

/** `strictEqual` would print a few thousand characters twice and leave you to spot the difference. */
export function assertSameStream(actual: string, expected: string): void {
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
