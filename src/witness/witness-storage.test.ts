import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, Indexer, Message } from "../cesr/main.ts";
import type { KeyEventBody, ReplyEventBody } from "../main.ts";
import { MemoryStore } from "./memory-store.ts";
import { WitnessStorage } from "./witness-storage.ts";

const STAMP = new Date("2026-01-01T00:00:00.000Z");

function storage() {
  return new WitnessStorage(new MemoryStore());
}

function event(aid: string, sn: string, sigs: string[] = []): Message<KeyEventBody> {
  const body = { v: "KERI10JSON000000_", t: "ixn", d: `E${sn}`, i: aid, s: sn, p: "E" };
  return new Message(body, sigs.length > 0 ? { ControllerIdxSigs: sigs } : undefined) as Message<KeyEventBody>;
}

describe(basename(import.meta.url), () => {
  // Unpadded, these sort as 0, 10, 100, 9, a, ff — so this fails the moment the
  // ordinal width is wrong, which is the one way `scan` silently misorders.
  test("should replay key events in numeric order across a hex width boundary", async () => {
    const store = storage();

    for (const sn of ["10", "9", "100", "a", "ff", "0"]) {
      await store.saveEvent(event("EAID", sn), STAMP);
    }

    assert.deepStrictEqual(
      (await Array.fromAsync(store.getKeyEvents("EAID"))).map((message) => message.body.s),
      ["0", "9", "a", "10", "ff", "100"],
    );
  });

  test("should round-trip attachments through the stored CESR", async () => {
    const store = storage();
    const sig = encodeText(Indexer.crypto.ed25519_sig(new Uint8Array(64), 0));

    await store.saveEvent(event("EAID", "0", [sig]), STAMP);

    const [stored] = await Array.fromAsync(store.getKeyEvents("EAID"));
    assert.deepStrictEqual(stored.attachments.ControllerIdxSigs, [sig]);
  });

  // The old schema keyed on (aid, sn) alone, so the second of a duplicitous pair
  // silently replaced the first and the evidence was gone.
  test("should keep both events of a duplicitous pair at one sequence number", async () => {
    const store = storage();
    const first = event("EAID", "1");
    const second = event("EAID", "1");
    second.body.d = "EOTHER";

    await store.saveEvent(first, STAMP);
    await store.saveEvent(second, new Date("2026-06-01T00:00:00.000Z"));

    assert.deepStrictEqual((await store.digestsAt("EAID", "1")).sort(), ["E1", "EOTHER"]);
  });

  test("should replay only the first-seen event of a duplicitous pair", async () => {
    const store = storage();
    const first = event("EAID", "1");
    const second = event("EAID", "1");
    second.body.d = "EOTHER";

    // Stored newest first, so a scan-order tiebreak would pick the wrong one.
    await store.saveEvent(second, new Date("2026-06-01T00:00:00.000Z"));
    await store.saveEvent(first, STAMP);

    const replayed = await Array.fromAsync(store.getKeyEvents("EAID"));
    assert.strictEqual(replayed.length, 1);
    assert.strictEqual(replayed[0].body.d, "E1");
  });

  // Positions shift when a receipt carries a subset, so keying on them lets a
  // later partial set land on top of a different signer's signature.
  test("should key a signature by its own index, not its position in the message", async () => {
    const store = storage();
    const sig = (at: number) => encodeText(Indexer.crypto.ed25519_sig(new Uint8Array(64).fill(at), at));

    await store.saveEvent(event("EAID", "0", [sig(0), sig(2)]), STAMP);
    await store.saveEvent(event("EAID", "0", [sig(1)]), STAMP);

    const [stored] = await Array.fromAsync(store.getKeyEvents("EAID"));
    assert.deepStrictEqual(stored.attachments.ControllerIdxSigs, [sig(0), sig(1), sig(2)]);
  });

  test("should keep the earliest first-seen stamp when an event is stored again", async () => {
    const store = storage();

    await store.saveEvent(event("EAID", "0"), STAMP);
    await store.saveEvent(event("EAID", "0"), new Date("2026-09-09T00:00:00.000Z"));

    const [stored] = await Array.fromAsync(store.getKeyEvents("EAID"));
    assert.strictEqual(stored.attachments.FirstSeenReplayCouples[0].dt.toISOString(), STAMP.toISOString());
  });

  test("should keep events for different AIDs apart", async () => {
    const store = storage();
    await store.saveEvent(event("EONE", "0"), STAMP);
    await store.saveEvent(event("ETWO", "0"), STAMP);

    assert.strictEqual((await Array.fromAsync(store.getKeyEvents("EONE"))).length, 1);
  });

  test("should read mailbox entries from an inclusive offset past a width boundary", async () => {
    const store = storage();
    for (let i = 0; i < 20; i++) {
      await store.saveMailboxEntry("EPRE", "credential", event("EX", String(i)));
    }

    assert.deepStrictEqual(
      (await Array.fromAsync(store.getMailboxEntries("EPRE", "credential", 15))).map((entry) => entry.id),
      [15, 16, 17, 18, 19],
    );
  });

  test("should land a bare and a slashed topic in the same key space", async () => {
    const store = storage();
    await store.saveMailboxEntry("EPRE", "credential", event("EX", "0"));
    await store.saveMailboxEntry("EPRE", "/credential", event("EX", "1"));

    assert.deepStrictEqual(
      (await Array.fromAsync(store.getMailboxEntries("EPRE", "/credential", 0))).map((entry) => entry.id),
      [0, 1],
    );
  });

  test("should prune the oldest entries but never restart the ordinal sequence", async () => {
    const store = storage();
    const pre = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    for (let i = 0; i < 1100; i++) {
      await store.saveMailboxEntry(pre, "credential", event("EX", String(i)));
    }

    const all = await Array.fromAsync(store.getMailboxEntries(pre, "credential", 0));
    assert.strictEqual(all.length, 1000, "retention cap holds");
    assert.strictEqual(all[all.length - 1].id, 1099, "ordinals keep climbing past the prune");
    assert.strictEqual(all[0].id, 100, "the oldest survivor is the cap behind the newest");
  });

  // A conditional store moves up rather than overwriting, which is the whole
  // reason `create` is on the port — the tail read is stale the moment a
  // second writer reads it too.
  test("should claim the next free ordinal when the slot is already taken", async () => {
    const backing = new MemoryStore();
    const store = new WitnessStorage(backing);

    await store.saveMailboxEntry("EPRE", "credential", event("EX", "0"));

    // Stands in for a racing writer: the tail now says 0, so the next deposit
    // resolves to 1 and finds it occupied.
    await backing.put("mbx:EPRE:credential:0000000000000001", "taken");

    await store.saveMailboxEntry("EPRE", "credential", event("EX", "2"));

    assert.strictEqual(await backing.get("mbx:EPRE:credential:0000000000000001"), "taken");
    assert.notStrictEqual(await backing.get("mbx:EPRE:credential:0000000000000002"), null);
  });

  test("should replace a role rather than accumulate one per registration", async () => {
    const store = storage();
    const role = (dt: string) =>
      new Message({
        v: "KERI10JSON000000_",
        t: "rpy",
        d: `E${dt}`,
        dt,
        r: "/end/role/add",
        a: { cid: "ECID", role: "mailbox", eid: "EEID" },
      }) as Message<ReplyEventBody>;

    await store.putRole(role("2026-01-01T00:00:00.000000+00:00"));
    await store.putRole(role("2026-02-01T00:00:00.000000+00:00"));

    const stored = await store.getRole("ECID", "mailbox", "EEID");
    assert.strictEqual(stored?.body.dt, "2026-02-01T00:00:00.000000+00:00");
  });
});
