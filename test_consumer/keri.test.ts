import assert from "node:assert";
import { describe, test } from "node:test";
import { Matter } from "cesr";
import * as surface from "keri";
import { generateKeyPair, KeyEventLog, keri, sign, verifySignature } from "keri";

describe("keri", () => {
  test("builds and verifies a key event log without storage or transport", () => {
    const current = generateKeyPair();
    const next = generateKeyPair();

    const icp = keri.incept({ signingKeys: [current.publicKey], nextKeys: [next.publicKeyDigest] });
    icp.attachments.ControllerIdxSigs.push(sign(icp.raw, { key: current.privateKey, index: 0 }));

    const log = KeyEventLog.empty().append(icp);

    assert.equal(log.state.identifier, icp.body.i);
    assert.deepEqual(log.state.signingKeys, [current.publicKey]);

    const detached = sign(icp.raw, { key: current.privateKey });
    assert.ok(verifySignature(icp.raw, Matter.parse(current.publicKey), Matter.parse(detached).raw));
  });

  test("exports no infrastructure", () => {
    const infra = [
      "Controller",
      "Witness",
      "Mailbox",
      "MailboxClient",
      "WitnessClient",
      "submitToWitnesses",
      "createListener",
      "createRouter",
      "createMailboxRouter",
      "SqliteControllerStorage",
      "NodeSqliteDatabase",
    ];

    for (const name of infra) {
      assert.ok(!(name in surface), `keri must not export ${name}`);
    }
  });

  test("exposes a single entry point", async () => {
    for (const subpath of ["keri/witness", "keri/mailbox", "keri/sqlite-storage", "keri/nodejs-utils"]) {
      await assert.rejects(
        () => import(subpath),
        (error: unknown) => {
          assert.equal((error as { code?: string }).code, "ERR_PACKAGE_PATH_NOT_EXPORTED");
          return true;
        },
        `${subpath} must not resolve`,
      );
    }
  });
});
