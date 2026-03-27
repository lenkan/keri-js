import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { formatDate } from "./events.ts";
import { exchange } from "./routed-event.ts";
import { cesr } from "cesr";
import { randomBytes } from "node:crypto";

describe("exchange", () => {
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

  test("create exchange event with embedded message", () => {
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

  test("create exchange event with embedded message attachments", () => {
    const sender = "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS";
    const embedded = exchange({
      sender,
      route: "/embedded",
    });

    const sigs = [cesr.index(cesr.crypto.ed25519_sig(randomBytes(64)), 0).text()];
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
});
