import assert from "node:assert";
import test, { describe } from "node:test";
import { createCredential } from "./credential.ts";

describe("Credential event", () => {
  test("Should create credential event", () => {
    const event = createCredential({
      i: "EAK1H-RJM-mRzgNa7oNTv71FBvJERCHLunYI9ja9KW7w",
      ri: "EEXV71avZSL6fKJnQky_oxHqRPlNYR3zNGD-OpJe0DJa",
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      a: {
        i: "EOdUAG4xgTpDeV8eMf1aZuFmaSOjMvDRcdpvAO48TM9A",
        dt: "2025-04-17T21:53:17.019676+00:00",
        name: "John Doe",
      },
      r: {
        usageDisclaimer: {
          l: "Usage disclaimer",
        },
        issuanceDisclaimer: {
          l: "Issuance disclaimer",
        },
      },
    });

    assert.deepStrictEqual(Object.keys(event.body), ["v", "d", "i", "ri", "s", "a", "r"]);
    assert.deepStrictEqual(event.body, {
      v: "ACDC10JSON000221_",
      d: "EFkmdBxaS4m0IfUCtx8Lq2Ikk3xk_g0IPZbVLR7YwT5C",
      i: "EAK1H-RJM-mRzgNa7oNTv71FBvJERCHLunYI9ja9KW7w",
      ri: "EEXV71avZSL6fKJnQky_oxHqRPlNYR3zNGD-OpJe0DJa",
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      a: {
        d: "EPHGIjOSzWt8Uus-3jjWMgGG-2k_5sShSHRW3XVpYYBf",
        i: "EOdUAG4xgTpDeV8eMf1aZuFmaSOjMvDRcdpvAO48TM9A",
        dt: "2025-04-17T21:53:17.019676+00:00",
        name: "John Doe",
      },
      r: {
        d: "EDw7zqfJv_f4XdMyw5nHd7trK3PqAu-JMRThxGBxpccQ",
        usageDisclaimer: {
          l: "Usage disclaimer",
        },
        issuanceDisclaimer: {
          l: "Issuance disclaimer",
        },
      },
    });
  });
});
