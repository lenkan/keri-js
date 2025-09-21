import { ed25519 } from "@noble/curves/ed25519.js";
import { cesr, CountCode_10, encodeCounter, IndexCode, MatterCode } from "cesr/__unstable__";
import { type InceptEvent, keri, type KeyEvent } from "./events/events.ts";
import {
  ControllerEventStore,
  type KeyEventMessage,
  type KeyState,
  type KeyValueStorage,
  resolveKeyStateSync,
} from "./events/event-store.ts";
import { encodeHexNumber, serializeAttachments, serializeReceipts, serializeSignatures } from "./serializer.ts";
import { MapStore } from "./main.ts";
import { parseKeyEvents } from "./client.ts";

export interface OobiArgs {
  aid?: string;
  role?: string;
}

export interface WitnessOptions {
  seed?: Uint8Array;
  url?: string;
  storage?: KeyValueStorage;
}

export class Witness {
  readonly #privateKey: Uint8Array<ArrayBufferLike>;
  readonly #publicKey: string;
  readonly #icp: InceptEvent;
  readonly #state: KeyState;
  readonly #options: WitnessOptions;
  readonly #db: ControllerEventStore;

  get state() {
    return this.#state;
  }

  constructor(options: WitnessOptions = {}) {
    this.#options = options;
    this.#db = new ControllerEventStore(options.storage ?? new MapStore());
    this.#privateKey = ed25519.utils.randomSecretKey(options.seed);
    this.#publicKey = cesr.encodeMatter({ code: MatterCode.Ed25519N, raw: ed25519.getPublicKey(this.#privateKey) });

    this.#icp = keri.incept({
      k: [this.#publicKey],
      kt: "1",
    });

    this.#db.save({
      event: this.#icp,
      signatures: [
        cesr.encodeIndexer({
          code: IndexCode.Ed25519_Sig,
          raw: ed25519.sign(new TextEncoder().encode(JSON.stringify(this.#icp)), this.#privateKey),
          index: 0,
        }),
      ],
      receipts: [],
    });

    this.#state = Object.freeze(
      resolveKeyStateSync([
        {
          event: this.#icp,
          signatures: [],
          receipts: [],
          timestamp: new Date(),
        },
      ]),
    );
  }

  #createResponse(messages: KeyEventMessage[]): Response {
    const body = messages
      .flatMap((message) => [
        JSON.stringify(message.event),
        serializeAttachments([
          serializeSignatures(message.signatures),
          serializeReceipts(message.receipts),
          encodeCounter({
            code: CountCode_10.FirstSeenReplayCouples,
            count: 1,
          }),
          encodeHexNumber(message.event.s ?? "0"),
          cesr.encodeDate(message.timestamp),
        ]),
      ])
      .join("");

    return new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/json+cesr" },
    });
  }

  async #oobi(request: Request): Promise<Response> {
    if (request.method.toUpperCase() !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const path = new URL(request.url).pathname;
    const match = path.match(/\/oobi\/?([A-Za-z0-9_-]+)?$/);

    if (!match) {
      return new Response("Not Found", { status: 404 });
    }

    const aid = match[1] ?? this.#icp.i;
    const messages = await this.#db.list(aid);

    if (messages.length === 0) {
      return new Response("Not Found", { status: 404 });
    }

    if (this.#options.url) {
      const scheme = new URL(this.#options.url).protocol.replace(":", "");

      const location = keri.reply({
        r: "/loc/scheme",
        a: {
          eid: this.#icp.i,
          scheme: scheme,
          url: this.#options.url,
        },
      });

      const endrole = keri.reply({
        r: "/end/role/add",
        a: {
          cid: this.#icp.i,
          role: "controller",
          eid: this.#icp.i,
        },
      });

      messages.push({
        event: location,
        signatures: [],
        // KERIpy adds controller signatures a receipt :/
        receipts: [{ backer: this.#icp.i, signature: this.#sign(location) }],
        timestamp: new Date(),
      });

      messages.push({
        event: endrole,
        signatures: [],
        // KERIpy adds controller signatures a receipt :/
        receipts: [{ backer: this.#icp.i, signature: this.#sign(endrole) }],
        timestamp: new Date(),
      });
    }

    const response = this.#createResponse(messages);
    response.headers.set("Keri-Aid", this.#icp.i);

    return response;
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

    const stream = new TextEncoder().encode(
      [JSON.stringify(event), request.headers.get("CESR-ATTACHMENT") ?? ""].join(""),
    );

    for await (const message of parseKeyEvents(stream)) {
      await this.#db.save(message);
    }

    return this.#createResponse([
      {
        event: keri.receipt({ d: event.d, i: event.i, s: event.s }),
        signatures: [],
        receipts: [{ backer: this.#icp.i, signature: this.#sign(event) }],
        timestamp: new Date(),
      },
    ]);
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
