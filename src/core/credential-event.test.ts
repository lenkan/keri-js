import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { issue } from "./credential-event.ts";

describe("Credential events", () => {
  test("Should create issuance event", () => {
    const event = issue({
      i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.deepEqual(Object.keys(event.body), ["v", "t", "d", "i", "s", "ri", "dt"]);
    assert.partialDeepStrictEqual(event.body, {
      v: "KERI10JSON0000ed_",
      t: "iss",
      i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });
  });
});
