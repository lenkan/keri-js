import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { issue, revoke } from "./credential-event.ts";

describe(basename(import.meta.url), () => {
  test("should create issuance event", () => {
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

  // KERI writes microseconds and a `Date` holds milliseconds, so a timestamp off the wire has to
  // travel as text. Rounding `…019676` to `…019000` would change the event's digest.
  test("should keep a timestamp given as a string", () => {
    const dt = "2025-04-17T21:53:17.019676+00:00";

    for (const event of [
      issue({
        i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
        ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
        dt,
      }),
      revoke({
        i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
        ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
        p: "EEUs6vfVMrXAwWmJAKX1yWtQTJ6AhCIEQF1K_HEXdNLC",
        dt,
      }),
    ]) {
      assert.equal(event.body.dt, dt);
    }
  });

  test("should format a timestamp given as a Date", () => {
    const event = issue({
      i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
      dt: new Date("2025-04-17T21:53:17.019Z"),
    });

    assert.equal(event.body.dt, "2025-04-17T21:53:17.019000+00:00");
  });
});
