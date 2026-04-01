import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter, type Message } from "../cesr/__main__.ts";
import { type KeyEventBody, keri } from "../core/main.ts";

export interface WitnessOptions {
  privateKey?: Uint8Array;
  url?: string;
}

export interface WitnessEvent {
  readonly message: Message;
  readonly timestamp: Date;
}

export interface Witness {
  readonly aid: string;
  readonly events: readonly WitnessEvent[];
  endorse(event: Message<KeyEventBody>): Message;
}

export function createWitness(options: WitnessOptions): Witness {
  const privateKey = options.privateKey ?? ed25519.utils.randomSecretKey();
  const publicKey = new Matter({ code: Matter.Code.Ed25519N, raw: ed25519.getPublicKey(privateKey) }).text();

  const icp = keri.incept({
    signingKeys: [publicKey],
    nextKeys: [],
  });

  const icpSig = Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey), 0).text();
  icp.attachments = { ControllerIdxSigs: [icpSig] };

  const events: WitnessEvent[] = [{ message: icp, timestamp: new Date() }];

  if (options.url) {
    const url = new URL(options.url);
    const scheme = url.protocol.replace(":", "");

    const location = keri.reply({
      r: "/loc/scheme",
      a: {
        eid: icp.body.i,
        scheme: scheme,
        url: options.url,
      },
    });

    const endrole = keri.reply({
      r: "/end/role/add",
      a: {
        cid: icp.body.i,
        role: "controller",
        eid: icp.body.i,
      },
    });

    location.attachments = {
      NonTransReceiptCouples: [{ prefix: icp.body.i, sig: sign(location) }],
    };

    endrole.attachments = {
      NonTransReceiptCouples: [{ prefix: icp.body.i, sig: sign(endrole) }],
    };

    events.push({ message: location, timestamp: new Date() });
    events.push({ message: endrole, timestamp: new Date() });
  }

  function sign(message: Message): string {
    const rawSignature = ed25519.sign(message.raw, privateKey);
    return new Matter({ code: Matter.Code.Ed25519_Sig, raw: rawSignature }).text();
  }

  function endorse(event: Message<KeyEventBody>): Message {
    const receipt = keri.receipt({ d: event.body.d, i: event.body.i, s: event.body.s });
    receipt.attachments = {
      NonTransReceiptCouples: [{ prefix: icp.body.i, sig: sign(event) }],
    };
    return receipt;
  }

  return {
    aid: icp.body.i,
    events,
    endorse,
  };
}
