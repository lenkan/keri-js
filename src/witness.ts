import { ed25519 } from "@noble/curves/ed25519.js";
import { cesr, IndexCode, MatterCode } from "cesr/__unstable__";
import { type InceptEvent, keri, type KeyEvent } from "./events/events.ts";
import { type KeyEventMessage } from "./main.ts";
import { serializeAttachments, serializeReceipts, serializeSignatures } from "./serializer.ts";

export interface OobiArgs {
  aid?: string;
  role?: string;
}

export interface WitnessOptions {
  seed?: Uint8Array;
}

export class Witness {
  readonly #privateKey: Uint8Array<ArrayBufferLike>;
  readonly #publicKey: string;
  readonly #icp: InceptEvent;
  readonly #signature: string;

  constructor(options: WitnessOptions = {}) {
    this.#privateKey = ed25519.utils.randomSecretKey(options.seed);
    this.#publicKey = cesr.encodeMatter({ code: MatterCode.Ed25519N, raw: ed25519.getPublicKey(this.#privateKey) });

    this.#icp = keri.incept({
      k: [this.#publicKey],
      kt: "1",
    });

    this.#signature = cesr.encodeIndexer({
      code: IndexCode.Ed25519_Sig,
      raw: ed25519.sign(new TextEncoder().encode(JSON.stringify(this.#icp)), this.#privateKey),
      index: 0,
    });
  }

  async oobi(): Promise<KeyEventMessage[]> {
    return [{ event: this.#icp, receipts: [], signatures: [this.#signature], timestamp: new Date() }];
  }

  #createResponse(message: KeyEventMessage): Response {
    const body = [
      JSON.stringify(message.event),
      serializeAttachments([serializeSignatures(message.signatures), serializeReceipts(message.receipts)]),
    ].join("");

    return new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/cesr+json" },
    });
  }

  async #oobi(request: Request): Promise<Response> {
    if (request.method.toUpperCase() !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const match = request.url.match(/\/oobi\/?([A-Za-z0-9_-])?$/);
    if (!match) {
      return new Response("Not Found", { status: 404 });
    }

    return this.#createResponse({
      event: this.#icp,
      signatures: [this.#signature],
      receipts: [],
      timestamp: new Date(),
    });
  }

  #sign(event: KeyEvent): string {
    const raw = new TextEncoder().encode(JSON.stringify(event));
    const sign = ed25519.sign(raw, this.#privateKey);

    return cesr.encodeMatter({ code: MatterCode.Ed25519_Sig, raw: sign });
  }

  async #receipt(request: Request): Promise<Response> {
    const event = (await request.json()) as KeyEvent;

    if (typeof event.i !== "string" || typeof event.d !== "string" || typeof event.s !== "string") {
      return new Response("Bad Request", { status: 400 });
    }

    return this.#createResponse({
      event: keri.receipt({ d: event.d, i: event.i, s: event.s }),
      signatures: [],
      receipts: [{ backer: this.#icp.i, signature: this.#sign(event) }],
      timestamp: new Date(),
    });
  }

  /**
   * Handle incoming HTTP requests
   *
   * @param request The incoming HTTP request
   */
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (url.pathname.startsWith("/oobi")) {
        return await this.#oobi(request);
      }

      if (url.pathname === "/receipts" && request.method.toUpperCase() === "POST") {
        return await this.#receipt(request);
      }

      return new Response("Not Found", { status: 404 });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("Error handling request:", err);
      return new Response("Internal Server Error", { status: 500 });
    }
  }
}
