import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, type Message } from "cesr";
import { KeyEventLog, keri } from "keri";

/**
 * Where a presentation waits between the holder delivering it and the browser
 * collecting it. Entries are short lived, so implementations are expected to
 * expire them rather than rely on the caller deleting them.
 */
export interface SessionStore {
  get(token: string): Promise<string | null>;
  put(token: string, cesr: string, ttlMs: number): Promise<void>;
}

export interface VerifierOptions {
  /**
   * Origin the verifier is reachable at. Must be a bare origin: KERIpy posts to
   * a hardcoded `/` under whatever URL the `/loc/scheme` reply advertises.
   */
  url: string;
  privateKey?: Uint8Array;
}

export class Verifier {
  readonly #privateKey: Uint8Array;
  readonly #kel: KeyEventLog;
  readonly #url: string;
  readonly events: readonly Message[];

  static createKEL(privateKey: Uint8Array): KeyEventLog {
    const publicKey = encodeText(new Matter({ code: Matter.Code.Ed25519N, raw: ed25519.getPublicKey(privateKey) }));
    const icp = keri.incept({ signingKeys: [publicKey], nextKeys: [] });
    icp.attachments = {
      ControllerIdxSigs: [encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey), 0))],
    };
    return KeyEventLog.from([icp]);
  }

  get aid(): string {
    return this.#kel.state.identifier;
  }

  get oobi(): string {
    return `${this.#url.replace(/\/$/, "")}/oobi`;
  }

  constructor(options: VerifierOptions) {
    this.#privateKey = options.privateKey ?? ed25519.utils.randomSecretKey();
    this.#kel = Verifier.createKEL(this.#privateKey);
    this.#url = options.url;

    const url = new URL(options.url);

    const location = keri.reply({
      r: "/loc/scheme",
      a: { eid: this.aid, scheme: url.protocol.replace(":", ""), url: options.url },
    });

    // `controller`, not `mailbox`: KERIpy's StreamPoster tries controller,
    // agent, then mailbox, and only the last one is store-and-forward. Claiming
    // the controller role is what makes `kli ipex grant` deliver straight here,
    // so the verifier needs no witness and no mailbox behind it.
    const endrole = keri.reply({
      r: "/end/role/add",
      a: { cid: this.aid, role: "controller", eid: this.aid },
    });

    location.attachments = {
      NonTransReceiptCouples: [{ prefix: this.aid, sig: this.#sign(location) }],
    };

    endrole.attachments = {
      NonTransReceiptCouples: [{ prefix: this.aid, sig: this.#sign(endrole) }],
    };

    this.events = [this.#kel.events[0], location, endrole];
  }

  #sign(message: Message): string {
    const rawSignature = ed25519.sign(message.raw, this.#privateKey);
    return encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: rawSignature }));
  }
}
