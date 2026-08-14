import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { parse } from "cesr";
import { EventIndex } from "./event-index.ts";

const ISSUER = "EAK1H-RJM-mRzgNa7oNTv71FBvJERCHLunYI9ja9KW7w";
const REGISTRY = "EEXV71avZSL6fKJnQky_oxHqRPlNYR3zNGD-OpJe0DJa";
const CREDENTIAL = "EKBG6wNsN9iT_gujAjOytqAyQdwtA24qc5C96xgu6Qy9";

async function fixture(name: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(new URL(`../../../../fixtures/${name}`, import.meta.url)));
}

async function messages(name: string) {
  return Array.fromAsync(parse(await fixture(name)));
}

describe(basename(import.meta.url), () => {
  test("should index the credential fixture by identifier and registry", async () => {
    const index = await EventIndex.parse(await fixture("credential.cesr"));

    assert.deepEqual(index.identifiers, [ISSUER]);
    assert.deepEqual(index.registries, [REGISTRY]);
    assert.deepEqual(
      index.credentials.map((c) => c.body.d),
      [CREDENTIAL],
    );
  });

  test("should group key events and registry events under their identifiers", async () => {
    const index = await EventIndex.parse(await fixture("credential.cesr"));

    assert.deepEqual(
      index.keyEvents(ISSUER).map((event) => event.body.t),
      ["icp", "ixn", "ixn"],
    );
    assert.deepEqual(
      index.transactionEvents(REGISTRY).map((event) => event.body.t),
      ["vcp", "iss"],
    );
  });

  test("should look up a credential by said", async () => {
    const index = await EventIndex.parse(await fixture("credential.cesr"));

    assert.equal(index.credential(CREDENTIAL)?.body.i, ISSUER);
    assert.equal(index.credential("EUnknown"), null);
  });

  test("should return empty results for unknown identifiers", async () => {
    const index = await EventIndex.parse(await fixture("credential.cesr"));

    assert.deepEqual(index.keyEvents("EUnknown"), []);
    assert.deepEqual(index.transactionEvents("EUnknown"), []);
  });

  test("should ignore duplicate events when messages are replayed", async () => {
    const parsed = await messages("credential.cesr");
    const index = new EventIndex([...parsed, ...parsed]);

    assert.equal(index.keyEvents(ISSUER).length, 3);
    assert.equal(index.transactionEvents(REGISTRY).length, 2);
    assert.equal(index.credentials.length, 1);
  });

  // KeyEventLog rejects a stream carrying two unrelated AIDs, so key events are
  // kept apart per identifier.
  test("should keep unrelated key event logs separate", async () => {
    const index = new EventIndex([...(await messages("credential.cesr")), ...(await messages("alice.cesr"))]);

    assert.equal(index.identifiers.length, 2);
    assert.equal(index.keyEvents(ISSUER).length, 3);
    assert.ok(index.keyEvents(ISSUER).every((event) => event.body.i === ISSUER));
  });

  test("should sort key events by sequence number regardless of stream order", async () => {
    const index = new EventIndex((await messages("credential.cesr")).toReversed());

    assert.deepEqual(
      index.keyEvents(ISSUER).map((event) => event.body.s),
      ["0", "1", "2"],
    );
  });

  // IPEX unwrapping is not implemented; grant.cesr carries its ACDC inside an
  // exn, which this ignores. Update when IPEX lands.
  test("should index no credentials from an IPEX grant stream", async () => {
    const index = await EventIndex.parse(await fixture("grant.cesr"));

    assert.deepEqual(index.credentials, []);
  });
});
