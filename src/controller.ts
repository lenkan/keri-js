import { Attachments, decodeMatter, encodeIndexer, IndexCode, MatterCode, Message, parse } from "cesr/__unstable__";
import {
  ControllerEventStore,
  type KeyValueStorage,
  type KeyEventSeal,
  type KeyState,
  type LocationRecord,
} from "./events/event-store.ts";
import type { Key, KeyManager } from "./keystore/key-manager.ts";
import {
  keri,
  type KeyEvent,
  type InteractEvent,
  type CredentialEvent,
  type RegistryInceptEvent,
  type IssueEvent,
  formatDate,
  type ReceiptEvent,
} from "./events/events.ts";
import { Client } from "./client.ts";

export interface ControllerDeps {
  keyManager: KeyManager;
  storage: KeyValueStorage;
}

export interface IpexGrantArgs {
  credential: CredentialEvent;
  recipient?: string;
  timestamp?: string;
}

export interface ForwardArgs {
  message: Message<KeyEvent>;
  sender: KeyState;
  topic: string;
  recipient: string;
  timestamp?: string;
}

export interface InceptArgs {
  keys?: Key[];
  wits?: string[];
  toad?: number;
}

export interface InteractArgs {
  aid: string;
  data: Record<string, unknown>;
}

export interface CreateRegistryArgs {
  owner: string;
  nonce?: string;
}

export interface CreateCredentialArgs {
  schemaId: string;
  registryId: string;
  holder: string;
  salt?: string;
  data?: Record<string, unknown>;
  rules?: Record<string, unknown>;
  edges?: Record<string, unknown>;
  timestamp?: Date;
}

export class Controller {
  #keyManager: KeyManager;
  #store: ControllerEventStore;

  get store() {
    return this.#store;
  }

  constructor(deps: ControllerDeps) {
    this.#store = new ControllerEventStore(deps.storage);
    this.#keyManager = deps.keyManager;
  }

  async createIdentifier(args: InceptArgs = {}): Promise<KeyState> {
    const keys = args.keys ?? [await this.#keyManager.incept()];

    const event = keri.incept({
      k: keys.map((key) => key.current),
      n: keys.map((key) => key.next),
      b: args.wits,
      bt: args.toad ? args.toad.toString(16) : undefined,
    });

    const sigs = await this.sign(
      event,
      keys.map((key) => key.current),
    );

    await this.#store.save(new Message(event, { ControllerIdxSigs: sigs }));
    const wigs = await this.submit(event, sigs);

    await this.#store.save(
      new Message(event, {
        ControllerIdxSigs: sigs,
        WitnessIdxSigs: wigs,
      }),
    );

    return await this.#store.state(event.i);
  }

  async interact(args: InteractArgs): Promise<InteractEvent> {
    const state = await this.state(args.aid);

    const sn = (parseInt(state.s ?? "0", 16) + 1).toString(16);
    const event = keri.interact({ i: state.i, p: state.d, s: sn, a: [args.data] });

    const sigs = await this.sign(event, state.k);

    await this.#store.save(new Message(event, { ControllerIdxSigs: sigs }));

    const wigs = await this.submit(event, sigs);
    await this.#store.save(
      new Message(event, {
        ControllerIdxSigs: sigs,
        WitnessIdxSigs: wigs,
      }),
    );

    return event;
  }

  async createRegistry(args: CreateRegistryArgs): Promise<RegistryInceptEvent> {
    const registry = keri.registry({
      ii: args.owner,
      n: args.nonce,
    });

    const anchor = await this.interact({
      aid: args.owner,
      data: {
        d: registry.d,
        s: registry.s,
        i: registry.i,
      },
    });

    const state = await this.state(args.owner);

    const message = new Message(registry, {
      SealSourceCouples: [
        {
          digest: anchor.d,
          snu: anchor.s,
        },
      ],
    });
    for (const wit of state.b) {
      const endpoint = await this.getClient(wit);

      await endpoint.sendMessage(message);
    }

    await this.#store.save(message);

    return registry;
  }

  async createCredential(args: CreateCredentialArgs): Promise<CredentialEvent> {
    const [registry] = (await this.#store.list(args.registryId)) as Message<RegistryInceptEvent>[];

    if (!registry) {
      throw new Error(`Registry ${args.registryId} not found`);
    }

    const state = await this.state(registry.body.ii);

    const acdc = keri.credential({
      i: state.i,
      ri: registry.body.i,
      s: args.schemaId,
      u: args.salt,
      a: {
        i: args.holder,
        dt: formatDate(args.timestamp ?? new Date()),
        ...args.data,
      },
      r: args.rules,
      e: args.edges,
    });

    const iss = keri.issue({
      i: acdc.d,
      ri: registry.body.i,
      dt: formatDate(args.timestamp ?? new Date()),
    });

    const anchor = await this.interact({
      aid: state.i,
      data: {
        d: iss.d,
        s: iss.s,
        i: iss.i,
      },
    });

    for (const wit of state.b) {
      const client = await this.getClient(wit);
      const message = new Message(iss, {
        SealSourceCouples: [
          {
            digest: anchor.d,
            snu: anchor.s,
          },
        ],
      });
      await client.sendMessage(message);
    }

    await this.#store.save(new Message(acdc, { SealSourceTriples: [{ prefix: anchor.i, digest: iss.d, snu: iss.s }] }));
    await this.#store.save(new Message(iss, { SealSourceCouples: [{ digest: anchor.d, snu: anchor.s }] }));

    return acdc;
  }

  async resolve(oobi: string) {
    const response = await fetch(oobi);
    if (!response.ok) {
      throw new Error(`Failed to fetch oobi: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error(`No body in response`);
    }

    for await (const event of parse(response.body)) {
      await this.#store.save(event as Message<KeyEvent>);
    }
  }

  async getClient(cid: string): Promise<Client> {
    // const
    const mailbox = await this.#store.endrole(cid, "mailbox");
    const agent = await this.#store.endrole(cid, "agent");
    const controller = await this.#store.endrole(cid, "controller");

    const event = controller || agent || mailbox;

    if (!event || !event.eid || typeof event.eid !== "string" || typeof event.role !== "string") {
      throw new Error(`No valid end role aid found for aid ${cid}`);
    }

    return new Client({ endpoint: await this.getLocation(event.eid), role: event.role });
  }

  async getLocation(aid: string): Promise<LocationRecord> {
    const location = await this.#store.location(aid);

    if (!location) {
      throw new Error(`No valid location found for aid ${aid}`);
    }

    if (!location.eid || typeof location.eid !== "string") {
      throw new Error(`No valid EID found for aid ${aid}`);
    }

    if (!location.scheme || typeof location.scheme !== "string") {
      throw new Error(`No valid scheme found for aid ${aid}`);
    }

    return {
      url: new URL(location.url).toString(),
      scheme: location.scheme,
      eid: location.eid,
    };
  }

  private async submit(event: KeyEvent, signatures: string[]): Promise<string[]> {
    if (!event || !("i" in event && typeof event.i === "string")) {
      throw new Error("No such event");
    }

    const state = await this.state(event.i);
    const receipts: Record<string, Message<ReceiptEvent>> = {};

    const wigs = new Set<string>();

    for (const wit of state.b) {
      const client = await this.getClient(wit);

      const message = new Message(event, { ControllerIdxSigs: signatures });
      const response = await client.getReceipt(message);

      if (response.attachments.NonTransReceiptCouples.length > 0) {
        const receiptCouple = response.attachments.NonTransReceiptCouples[0];
        const witnessIndex = state.b.indexOf(receiptCouple.prefix);

        if (witnessIndex !== -1) {
          const signature = decodeMatter(receiptCouple.sig);
          wigs.add(
            encodeIndexer({
              code: getIndexedCode(signature.code),
              raw: signature.raw,
              index: witnessIndex,
            }),
          );
        }
      }
      await this.#store.save(response);

      receipts[wit] = response;
    }

    for (const wit of state.b) {
      const client = await this.getClient(wit);

      for (const [other, receipt] of Object.entries(receipts)) {
        if (other === wit) {
          continue;
        }

        const message = new Message(receipt.body, {
          NonTransReceiptCouples: receipt.attachments.NonTransReceiptCouples,
        });
        await client.sendMessage(message);
      }
    }

    return Array.from(wigs);
  }

  async state(said: string): Promise<KeyState> {
    if (typeof said !== "string") {
      throw new Error(`said must be a string, got ${typeof said}`);
    }

    if (!said) {
      throw new Error("said cannot be empty string");
    }

    const result = await this.#store.state(said);

    if (!result) {
      throw new Error(`No state found for said ${said}`);
    }

    return result;
  }

  async listEvents(id: string): Promise<Message<KeyEvent>[]> {
    return this.#store.list(id);
  }

  async sendCredentialArficats(credential: CredentialEvent, recipient: string): Promise<void> {
    const client = await this.getClient(recipient);
    const state = await this.state(credential.i);

    if (credential.e) {
      for (const [, edge] of Object.entries(credential.e)) {
        if (typeof edge === "object" && "n" in edge && typeof edge.n === "string") {
          const source = await this.store.get(edge.n);

          if (!source) {
            throw new Error(`No source found for edge ${edge.n}`);
          }

          if (!source.body.v.startsWith("ACDC")) {
            throw new Error(`Source for edge ${edge.n} is not a credential`);
          }

          await this.sendCredentialArficats(source.body as CredentialEvent, recipient);

          if (
            (source.attachments.SealSourceCouples.length || source.attachments.SealSourceTriples.length) &&
            source.body.i &&
            typeof source.body.i === "string"
          ) {
            await this.forward(client, {
              message: source,
              recipient: recipient,
              sender: await this.state(source.body.i),
              topic: "credential",
            });
          }
        }
      }
    }

    // Introduce sender to mailbox
    for (const message of await this.#store.list(state.i)) {
      await client.sendMessage(message);
    }

    // Introduce sender to recipient
    for (const message of await this.#store.list(state.i)) {
      await this.forward(client, {
        message: message,
        recipient: recipient,
        sender: state,
        topic: "credential",
      });
    }

    // Introduce registry to recipient
    for (const message of await this.#store.list(credential.ri)) {
      if (!message.attachments.SealSourceCouples.length && !message.attachments.SealSourceTriples.length) {
        throw new Error("No seal found for registry");
      }

      await this.forward(client, {
        message: message,
        recipient,
        sender: state,
        topic: "credential",
      });
    }

    // Introduce transaction to recipient
    for (const message of await this.#store.list(credential.d)) {
      if (!message.attachments.SealSourceCouples.length && !message.attachments.SealSourceTriples.length) {
        throw new Error("No seal found for issuance");
      }

      await this.forward(client, {
        message: message,
        recipient,
        sender: state,
        topic: "credential",
      });
    }
  }

  async grant(args: IpexGrantArgs): Promise<void> {
    const state = await this.state(args.credential.i);
    const [registry] = await this.listEvents(args.credential.ri);

    if (!registry) {
      throw new Error(`Registry not found for said ${args.credential.ri}`);
    }

    const recipient = args.recipient || args.credential.a.i;
    if (!recipient) {
      throw new Error(`No recipient specified and the credential has no issuee`);
    }

    const client = await this.getClient(recipient);

    const seal: KeyEventSeal = {
      i: state.i,
      s: state.ee.s,
      d: state.ee.d,
    };

    const transactions = await this.#store.list(args.credential.d);
    const [iss] = transactions as Message<IssueEvent>[];

    if (!iss) {
      throw new Error(`No issuance found for said ${args.credential.d}`);
    }

    const anchorSeal = iss.attachments.SealSourceCouples[0] || iss.attachments.SealSourceTriples[0];
    if (!anchorSeal) {
      throw new Error(`No seal found for issuance ${iss.body.d}`);
    }

    const anchor = await this.#store.get(anchorSeal.digest);

    if (!anchor) {
      throw new Error(`No anchor found for issuance ${iss.body.d}`);
    }

    const grant = keri.exchange({
      i: state.i,
      r: "/ipex/grant",
      dt: args.timestamp,
      q: {},
      a: {
        m: "",
        i: recipient,
      },
      e: {
        acdc: args.credential,
        iss: iss.body,
        anc: anchor.body,
      },
    });

    const grantsigs = await this.sign(grant, state.k);
    const message = new Message(grant, {
      grouped: false,
      TransIdxSigGroups: [
        {
          snu: seal.s,
          digest: seal.d,
          prefix: seal.i,
          ControllerIdxSigs: grantsigs,
        },
      ],
      PathedMaterialCouples: [
        {
          path: "-e-acdc",
          attachments: {
            grouped: false,
            SealSourceTriples: [
              {
                prefix: iss.body.i,
                snu: iss.body.s,
                digest: iss.body.d,
              },
            ],
          },
        },
        {
          path: "-e-iss",
          attachments: {
            grouped: true,
            SealSourceCouples: [
              {
                digest: anchor.body.d,
                snu: anchor.body.s as string,
              },
            ],
          },
        },
        {
          path: "-e-anc",
          attachments: {
            grouped: true,
            ControllerIdxSigs: anchor.attachments.ControllerIdxSigs,
            WitnessIdxSigs: anchor.attachments.WitnessIdxSigs,
            FirstSeenReplayCouples: anchor.attachments.FirstSeenReplayCouples,
          },
        },
      ],
    });

    await this.forward(client, {
      message,
      recipient,
      sender: state,
      topic: "credential",
      timestamp: args.timestamp,
    });
  }

  async forward(client: Client, args: ForwardArgs): Promise<void> {
    if (client.role !== "mailbox" && client.role !== "witness") {
      // throw new Error("Can only forward to mailbox or witness endpoints");
      if (args.message.attachments.frames().length > 1) {
        await client.sendMessage(args.message);
        return;
      }

      const sigs = await this.sign(args.message.body, args.sender.k);
      const message = new Message(args.message.body, {
        grouped: false,
        ControllerIdxSigs: sigs,
      });

      await client.sendMessage(message);
      return;
    }

    const fwd = keri.exchange({
      i: args.sender.i,
      r: "/fwd",
      dt: args.timestamp,
      // rp: args.recipient,
      q: { pre: args.recipient, topic: args.topic },
      a: {},
      e: {
        evt: args.message.body,
      },
    });

    const fwdsigs = await this.sign(fwd, args.sender.k);
    const hasAttachments = args.message.attachments.frames().length > 1;

    const evtatc = hasAttachments
      ? args.message.attachments
      : new Attachments({
          grouped: false,
          TransIdxSigGroups: [
            {
              digest: args.sender.ee.d,
              snu: args.sender.ee.s,
              prefix: args.sender.i,
              ControllerIdxSigs: await this.sign(args.message.body, args.sender.k),
            },
          ],
        });

    const atc = new Attachments({
      grouped: false,
      TransIdxSigGroups: [
        {
          ControllerIdxSigs: fwdsigs,
          snu: args.sender.ee.s,
          digest: args.sender.ee.d,
          prefix: args.sender.i,
        },
      ],
      PathedMaterialCouples: [
        {
          path: "-e-evt",
          attachments: evtatc,
        },
      ],
    });

    const message = new Message(fwd, atc);

    await client.sendMessage(message);
  }

  async sign(event: Record<string, unknown>, keys: string[]): Promise<string[]> {
    const encoder = new TextEncoder();
    const payload = encoder.encode(JSON.stringify(event));
    const sigs = await Promise.all(keys.map((key, idx) => this.#keyManager.sign(key, payload, idx)));
    return sigs;
  }
}
export function getIndexedCode(code: string): string {
  switch (code) {
    case MatterCode.Ed25519_Sig:
      return IndexCode.Ed25519_Sig;
    case MatterCode.Ed448_Sig:
      return IndexCode.Ed448_Sig;
    default:
      throw new Error(`Unsupported indexed signature type: ${code}`);
  }
}
