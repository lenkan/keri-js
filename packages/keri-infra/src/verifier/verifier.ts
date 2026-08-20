import { ed25519 } from "@noble/curves/ed25519.js";
import type { Message } from "cesr";
import { ed25519Signer, KeyEvent, KeyEventLog, RoutedEvent, type Signer, signEvent } from "keri";

/**
 * TTL'd string KV holding everything a session needs: the presentation waiting
 * for the browser, the login record, and the words → token correlation, kept
 * apart by key prefix. Entries are short lived, so implementations are expected
 * to expire them rather than rely on the caller deleting them.
 */
export interface SessionStore {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, ttlMs: number): Promise<void>;
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
  readonly #kel: KeyEventLog;
  readonly #url: string;
  readonly events: readonly Message[];

  static async createKEL(signer: Signer): Promise<KeyEventLog> {
    const icp = KeyEvent.incept({ signingKeys: [signer.publicKey], nextKeyDigests: [] });
    await signEvent(icp, [signer]);
    return KeyEventLog.from([icp]);
  }

  get aid(): string {
    return this.#kel.state.identifier;
  }

  get oobi(): string {
    return `${this.#url}/oobi`;
  }

  static async create(options: VerifierOptions): Promise<Verifier> {
    const signer = ed25519Signer(options.privateKey ?? ed25519.utils.randomSecretKey(), { nonTransferable: true });
    const kel = await Verifier.createKEL(signer);
    const aid = kel.state.identifier;

    const url = new URL(options.url);

    // Stripped once, and advertised in the same form: KERIpy appends a hardcoded
    // `/`, so a trailing slash here would have it post to `//`, which routes
    // nowhere.
    const base = options.url.replace(/\/+$/, "");

    const location = RoutedEvent.reply({
      r: "/loc/scheme",
      a: { eid: aid, scheme: url.protocol.replace(":", ""), url: base },
    });

    // `controller`, not `mailbox`: KERIpy's StreamPoster tries controller,
    // agent, then mailbox, and only the last one is store-and-forward. Claiming
    // the controller role is what makes `kli ipex grant` deliver straight here,
    // so the verifier needs no witness and no mailbox behind it.
    const endrole = RoutedEvent.reply({
      r: "/end/role/add",
      a: { cid: aid, role: "controller", eid: aid },
    });

    location.attachments = {
      NonTransReceiptCouples: [{ prefix: aid, sig: await signer.sign(location.raw) }],
    };

    endrole.attachments = {
      NonTransReceiptCouples: [{ prefix: aid, sig: await signer.sign(endrole.raw) }],
    };

    return new Verifier(kel, base, [kel.events[0], location, endrole]);
  }

  private constructor(kel: KeyEventLog, url: string, events: readonly Message[]) {
    this.#kel = kel;
    this.#url = url;
    this.events = events;
  }
}
