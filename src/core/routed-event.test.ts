import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, Indexer, Message } from "../cesr/main.ts";
import { formatDate } from "./events.ts";
import { exchange, isExchange, isQuery, isReply, isRoutedEvent, query, reply } from "./routed-event.ts";

describe(basename(import.meta.url), () => {
  test("should create exchange event", () => {
    const dt = formatDate(new Date());
    const event = exchange({
      sender: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      route: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      timestamp: dt,
    });

    assert.partialDeepStrictEqual(event.body, { t: "exn" });
    assert.deepStrictEqual(event.body.e, {});
  });

  test("should create exchange event with embedded message", () => {
    const sender = "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS";
    const event = exchange({
      sender,
      route: "/fwd",
      embeds: {
        foo: exchange({
          sender,
          route: "/embedded",
        }),
      },
    });

    assert.partialDeepStrictEqual(event.body, {
      i: sender,
      r: "/fwd",
      e: {
        foo: {
          i: sender,
          r: "/embedded",
          e: {},
        },
      },
    });
  });

  test("should create exchange event with embedded message attachments", () => {
    const sender = "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS";
    const embedded = exchange({
      sender,
      route: "/embedded",
    });

    const sigs = [encodeText(Indexer.crypto.ed25519_sig(randomBytes(64), 0))];
    embedded.attachments = { ControllerIdxSigs: sigs };

    const event = exchange({
      sender,
      route: "/fwd",
      embeds: {
        foo: embedded,
      },
    });

    assert.partialDeepStrictEqual(event.body, {
      r: "/fwd",
      e: {
        foo: {
          i: sender,
          r: "/embedded",
          e: {},
        },
      },
    });

    const resultAttachments = event.attachments.PathedMaterialCouples[0];
    assert.partialDeepStrictEqual(resultAttachments, { path: "-e-foo", grouped: true });
    assert.deepStrictEqual(resultAttachments.attachments.ControllerIdxSigs, sigs);
  });

  describe("type guards", () => {
    const sender = "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS";
    const qry = query({ q: {}, r: "mbx" });
    const rpy = reply({ r: "/loc/scheme", a: {} });
    const exn = exchange({ sender, route: "/fwd" });
    const stub = (t: string) => new Message({ v: "KERI10JSON000000_", t, d: "", i: "" } as never);

    test("isQuery should narrow to qry only", () => {
      assert.equal(isQuery(qry), true);
      assert.equal(isQuery(rpy), false);
      assert.equal(isQuery(exn), false);
      assert.equal(isQuery(stub("icp")), false);
    });

    test("isReply should narrow to rpy only", () => {
      assert.equal(isReply(rpy), true);
      assert.equal(isReply(qry), false);
      assert.equal(isReply(exn), false);
      assert.equal(isReply(stub("rct")), false);
    });

    test("isExchange should narrow to exn only", () => {
      assert.equal(isExchange(exn), true);
      assert.equal(isExchange(qry), false);
      assert.equal(isExchange(rpy), false);
    });

    test("isRoutedEvent should be true for qry/rpy/exn and false for others", () => {
      assert.equal(isRoutedEvent(qry), true);
      assert.equal(isRoutedEvent(rpy), true);
      assert.equal(isRoutedEvent(exn), true);
      assert.equal(isRoutedEvent(stub("icp")), false);
      assert.equal(isRoutedEvent(stub("rct")), false);
      assert.equal(isRoutedEvent(stub("vcp")), false);
    });
  });
});
