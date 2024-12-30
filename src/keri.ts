import { program } from "commander";
import { parseStream } from "./parser/parser.ts";
import { SaltyKey } from "./cesr/keys.ts";
import { CounterCode, MatterCode } from "./parser/codes.ts";
import libsodium from "libsodium-wrappers-sumo";
import { incept } from "./event.ts";
import cesr from "./parser/cesr-encoding.ts";
import { Base64 } from "./cesr/base64.ts";

program.command("parse").action(async () => {
  const stream = process.stdin;

  for await (const event of parseStream(ReadableStream.from(stream))) {
    console.log(event);
  }
});

program
  .command("incept")
  .requiredOption("--passcode <passcode>")
  .requiredOption("--name <name>")
  .action(async ({ passcode, name }) => {
    await libsodium.ready;

    if (typeof passcode !== "string") {
      throw new Error(`Invalid passcode`);
    }

    if (typeof name !== "string") {
      throw new Error(`Invalid name`);
    }

    const salt = `${MatterCode.Salt_128}${passcode.slice(0, 22).padStart(22, "A")}`;
    const keys = [new SaltyKey({ salt, password: `${name}00` })];
    const next = [new SaltyKey({ salt, password: `${name}11` })];

    const wits = ["http://127.0.0.1:5642"];

    const b = ["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"];

    const payload = incept({
      kt: "1",
      k: keys.map((key) => key.publicKey),
      nt: "1",
      n: next.map((next) => next.publicKeyDigest),
      bt: "1",
      b,
    });

    const sigs = keys.map((key, index) => {
      const sig = key.sign(new TextEncoder().encode(JSON.stringify(payload)));
      return cesr.index(sig, index);
    });

    const sigGroup = `${CounterCode.ControllerIdxSigs}${Base64.fromInt(sigs.length, 2)}${sigs.join("")}`;

    const attachmentSize = new TextEncoder().encode(sigGroup).length / 4;
    const attachment = `${CounterCode.AttachmentGroup}${Base64.fromInt(attachmentSize, 2)}${sigGroup}`;

    for (const wit of wits) {
      const url = new URL("/receipts", wit);

      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify(payload),
        headers: {
          "Content-Type": "application/cesr+json",
          "CESR-ATTACHMENT": attachment,
        },
      });

      if (response.body) {
        for await (const receipt of parseStream(response.body)) {
          console.log(receipt);
        }
      }
    }

    console.dir({
      payload: payload,
      sigs,
      attachment,
    });
  });

program.parse(process.argv);
