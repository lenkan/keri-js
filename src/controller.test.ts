import { beforeEach, test, mock, describe } from "node:test";
import assert from "node:assert";
import { parse } from "cesr";
import { formatDate, keri } from "./events/events.ts";
import { type Key, KeyManager } from "./keystore/key-manager.ts";
import { Controller } from "./controller.ts";
import { SqliteStorage } from "./db/storage-sqlite.ts";
import { privateKey00, privateKey11 } from "../fixtures/keys.ts";
import { PassphraseEncrypter } from "./keystore/encrypt.ts";
import { type KeyState } from "./events/event-store.ts";
import { KeyEventMessage } from "./events/message.ts";

let storage: SqliteStorage;
let controller: Controller;
let keyManager: KeyManager;

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const output: T[] = [];
  for await (const item of iterable) {
    output.push(item);
  }
  return output;
}

const recipient = "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM";
const mailbox = "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha";

beforeEach(async () => {
  storage = new SqliteStorage();
  keyManager = new KeyManager({
    encrypter: new PassphraseEncrypter("password"),
    storage,
  });
  controller = new Controller({ storage, keyManager });

  storage.init();

  await controller.store.save(
    new KeyEventMessage(
      keri.reply({
        r: "/loc/scheme",
        a: {
          eid: mailbox,
          scheme: "http",
          url: "http://localhost:5642",
        },
      }),
    ),
  );

  await controller.store.save(
    new KeyEventMessage(
      keri.reply({
        r: "/end/role/add",
        a: {
          eid: mailbox,
          cid: recipient,
          role: "mailbox",
        },
      }),
    ),
  );
});

describe("When identifier is created", () => {
  let key: Key;
  let state: KeyState;
  const fetch = mock.method(globalThis, "fetch", () => {
    return Response.json({});
  });

  beforeEach(async () => {
    fetch.mock.resetCalls();
    key = await keyManager.import(privateKey00, privateKey11);
    state = await controller.createIdentifier({ keys: [key] });
  });

  test("Should include inception event in event list", async () => {
    const list = await controller.listEvents(state.i);

    const [icp] = list;

    assert.deepStrictEqual(icp.event.t, "icp");
    assert.deepStrictEqual(icp.event.d, state.ee.d);
    assert.deepStrictEqual(icp.event.s, "0");
  });

  test("Forward exchange event", async () => {
    const client = await controller.getClient(recipient);

    const timestamp = formatDate(new Date(Date.parse("2023-10-01T00:00:00Z")));
    const event = keri.exchange({
      dt: timestamp,
      i: state.i,
      r: "/challenge/response",
    });
    const exn = new KeyEventMessage(event, {
      seal: {
        i: state.i,
        d: state.d,
        s: state.s,
      },
      sigs: await controller.sign(event, state.k),
    });

    await controller.forward(client, {
      sender: await controller.state(state.i),
      topic: "challenge",
      recipient: recipient,
      timestamp: timestamp,
      message: exn,
    });

    const headers = fetch.mock.calls[0].arguments[1]?.headers ?? {};
    const body = new TextDecoder().decode(fetch.mock.calls[0].arguments[1]?.body as Uint8Array);
    const [message] = await collect(parse(body + headers["CESR-ATTACHMENT"], { version: 1 }));

    // TODO: Slice because to remove wrapping attachment group
    assert.deepStrictEqual(message.attachments.slice(1), [
      "-FAB",
      "EK0jhXxTQQgBKKcDLpmPhU5Mt5kK6tJXRjNl3fsVrUqU",
      "0AAAAAAAAAAAAAAAAAAAAAAA",
      "EK0jhXxTQQgBKKcDLpmPhU5Mt5kK6tJXRjNl3fsVrUqU",
      "-AAB",
      "AADHI3wDprYdXv0YHImildstc0yg0Wm-0BBMEzFdpAejiTiGh14wzgX4Z0vVtzAHykFT9bZzt9heArbAU24HXNoI",
      "-LA3",
      "5AACAA-e-evt",
      "-FAB",
      "EK0jhXxTQQgBKKcDLpmPhU5Mt5kK6tJXRjNl3fsVrUqU",
      "0AAAAAAAAAAAAAAAAAAAAAAA",
      "EK0jhXxTQQgBKKcDLpmPhU5Mt5kK6tJXRjNl3fsVrUqU",
      "-AAB",
      "AABn3K1qm3CF57lKqa6AQ4QuVM4w2dy1xLjQy0nqllMcRBaj1h20Ibd0yFHKxGb4tJfJKxguO89sTEwrlQUNcT4C",
    ]);
  });

  test("Forward grant message to recipient", async () => {
    const registry = await controller.createRegistry({
      owner: state.i,
      nonce: "0AMdSIIu9adDdMMNGtMTa_KBNMxZEiUjlAxDTGbGgulqD",
    });

    const timestamp = new Date(Date.parse("2023-10-01T00:00:00Z"));
    const credential = await controller.createCredential({
      timestamp,
      holder: recipient,
      registryId: registry.i,
      schemaId: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      data: {
        LEI: "123123123123123",
      },
      rules: {
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
    });

    await controller.grant({ credential, timestamp: formatDate(timestamp) });

    const [, request] = fetch.mock.calls[0].arguments;
    const headers = request?.headers ?? {};
    const body = JSON.parse(new TextDecoder().decode(request?.body as Uint8Array));
    const expected = [
      "-FAB",
      state.i,
      "0AAAAAAAAAAAAAAAAAAAAAAA",
      state.d,
      "-AAB",
      "AAAmJGeW1ukXm1ZsZnEgh8ZpSIIL-y5Djlwcnu-fY1hr9porKzaC6tgwhAzxp0LJwKSr1oeWff-wFCg0SDtlONwL",
      "-LCb",
      "5AACAA-e-evt",
      "-FAB",
      state.i,
      "0AAAAAAAAAAAAAAAAAAAAAAA",
      state.d,
      "-AAB",
      "AADItTlqc_Fbcv3SlpYFKx2R_h1jDB92NGFIR59_w1TLlGWMmKRjKktwwltte4JiSHa19UNaqHznx8tJuWsxnfUJ",
      "-LAg",
      "4AACA-e-acdc",
      "-IAB",
      "EJhq8L9rwzT5wUnpk2ttzVE9Xn6QX-QSbo3XxQMg3MsF",
      "0AAAAAAAAAAAAAAAAAAAAAAA",
      "EHuMpe3OaeAQyyvTpyTAcCGoWzVnX_PZDHSh1bcJdrNh",
      "-LAW",
      "5AACAA-e-iss",
      "-VAS",
      "-GAB",
      "0AAAAAAAAAAAAAAAAAAAAAAC",
      "ECIqfv8yo8-oJtqplxCNAm9KZf7PWFENTWi1dxATIYgw",
      "-LAr",
      "5AACAA-e-anc",
      "-VAn",
      "-AAB",
      "AADqmCIhCa0O_TYbVhpEyz-XxEGqZzHlXl-Bjw1GtPyGkj2TxiYpjIm_On8qNBMX_3MNfKeTu4dTVhf9z39anmgI",
      "-EAB",
      "0AAAAAAAAAAAAAAAAAAAAAAC",
    ];

    const [message] = await collect(parse(JSON.stringify(body) + headers["CESR-ATTACHMENT"], { version: 1 }));

    assert.partialDeepStrictEqual(message.payload, {
      d: "EDp3UvrqHr1MTcJjP59zFF-L0w-QUShdXbwX8xHgaF3x",
      t: "exn",
    });
    assert.deepStrictEqual(message.attachments.slice(1, -1), expected);
  });

  test("Create credential", async () => {
    const registry = await controller.createRegistry({ owner: state.i });
    const credential = await controller.createCredential({
      holder: recipient,
      registryId: registry.i,
      schemaId: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      data: {
        LEI: "123123123123123",
      },
      rules: {
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
    });

    assert.partialDeepStrictEqual(credential, {
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      i: state.i,
      a: {
        LEI: "123123123123123",
      },
    });
  });
});

test("Create chained credential", async () => {
  const holder = await controller.createIdentifier();
  const issuer = await controller.createIdentifier();
  const registry = await controller.createRegistry({ owner: issuer.i });
  const LEI0 = "123123123123123";
  const LEI1 = "123123123123124";

  const credential0 = await controller.createCredential({
    holder: holder.i,
    registryId: registry.i,
    schemaId: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    data: {
      LEI: LEI0,
    },
    rules: {
      usageDisclaimer: {
        l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
      },
      issuanceDisclaimer: {
        l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
      },
    },
  });

  const credential1 = await controller.createCredential({
    holder: holder.i,
    registryId: registry.i,
    schemaId: "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
    data: {
      LEI: LEI1,
    },
    rules: {
      usageDisclaimer: {
        l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
      },
      issuanceDisclaimer: {
        l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
      },
    },
    edges: {
      qvi: {
        n: credential0.d,
        s: credential0.s,
      },
    },
  });

  assert.partialDeepStrictEqual(credential0, {
    s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    i: issuer.i,
    a: {
      LEI: LEI0,
    },
    r: {},
  });

  assert.partialDeepStrictEqual(credential1, {
    s: "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
    i: issuer.i,
    a: {
      LEI: LEI1,
    },
    e: {
      qvi: {
        n: credential0.d,
        s: credential0.s,
      },
    },
  });
});
