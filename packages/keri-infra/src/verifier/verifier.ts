import { ed25519 } from "@noble/curves/ed25519.js";
import type { Message } from "cesr";
import { ed25519Signer, endorse, KeyEvent, KeyEventLog, RoutedEvent, type Signer, signEvent } from "keri";

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
    signEvent(icp, { signers: [signer] });
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

    // Stripped once, and advertised in the same form: KERIpy composes request
    // paths onto whatever the location advertises (kli mailbox add appends
    // /mailboxes, sendDirect appends /), so the base must be a bare origin.
    // Requires keripy >= 1.3.6 — older kli composed a bare-origin location
    // into the scheme-relative "//mailboxes" and refused it.
    const base = options.url.replace(/\/+$/, "");

    const location = RoutedEvent.reply({
      r: "/loc/scheme",
      a: { eid: aid, scheme: url.protocol.replace(":", ""), url: base },
    });

    // `controller`, and deliberately NOT `mailbox`: controller is what makes
    // KERIpy's Poster deliver grants and challenge responses straight here —
    // and advertising a mailbox role for the portal itself would make KERIpy
    // send every message twice (Poster sends to ALL advertised roles). The
    // portal still acts as a mailbox for enrolled users: `kli mailbox add`
    // needs only the location, and each user's own end-role names this AID.
    const endrole = RoutedEvent.reply({
      r: "/end/role/add",
      a: { cid: aid, role: "controller", eid: aid },
    });

    endorse(location, { signers: [signer], state: kel.state });
    endorse(endrole, { signers: [signer], state: kel.state });

    return new Verifier(kel, base, [kel.events[0], location, endrole]);
  }

  private constructor(kel: KeyEventLog, url: string, events: readonly Message[]) {
    this.#kel = kel;
    this.#url = url;
    this.events = events;
  }
}
