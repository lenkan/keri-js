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
  type InteractEvent,
  type CredentialEvent,
  type RegistryInceptEvent,
  type IssueEvent,
  formatDate,
  type ReceiptEvent,
} from "./events/events.ts";
import { Client, parseKeyEvents as parseMessages } from "./client.ts";
import { KeyEventMessage } from "./events/message.ts";
import { Attachments } from "./events/attachments.ts";
import { cesr } from "cesr/__unstable__";
import { getIndexedCode } from "./serializer.ts";

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
  message: KeyEventMessage;
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

    const message = new KeyEventMessage(event, { sigs });

    await this.#store.save(message);
    await this.submit(message);

    return await this.#store.state(message.event.i);
  }

  async interact(args: InteractArgs): Promise<InteractEvent> {
    const state = await this.state(args.aid);

    const sn = (parseInt(state.s ?? "0", 16) + 1).toString(16);
    const event = keri.interact({ i: state.i, p: state.d, s: sn, a: [args.data] });

    const sigs = await this.sign(event, state.k);
    const message = new KeyEventMessage(event, { sigs });

    await this.#store.save(message);
    await this.submit(message);

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

    const message = new KeyEventMessage(registry, { source: { i: anchor.i, s: anchor.s, d: anchor.d } });
    for (const wit of state.b) {
      const endpoint = await this.getClient(wit);
      await endpoint.sendMessage(message);
    }

    await this.#store.save(message);

    return registry;
  }

  async createCredential(args: CreateCredentialArgs): Promise<CredentialEvent> {
    const [registry] = (await this.#store.list(args.registryId)) as KeyEventMessage<RegistryInceptEvent>[];

    if (!registry) {
      throw new Error(`Registry ${args.registryId} not found`);
    }

    const state = await this.state(registry.event.ii);

    const acdc = keri.credential({
      i: state.i,
      ri: registry.event.i,
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
      ri: registry.event.i,
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

    const issMessage = new KeyEventMessage(iss, {
      source: { i: anchor.i, s: anchor.s, d: anchor.d },
    });

    for (const wit of state.b) {
      const client = await this.getClient(wit);
      await client.sendMessage(issMessage);
    }

    await this.#store.save(
      new KeyEventMessage(acdc, {
        source: { i: iss.i, s: iss.s, d: iss.d },
      }),
    );

    await this.#store.save(issMessage);

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

    for await (const message of parseMessages(response.body)) {
      await this.#store.save(message);
    }
  }

  async getClient(cid: string): Promise<Client> {
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

  async submit(message: KeyEventMessage): Promise<void> {
    if (!message.event || !("i" in message.event && typeof message.event.i === "string")) {
      throw new Error("No such event");
    }

    const state = await this.state(message.event.i);
    const receipts: Record<string, KeyEventMessage<ReceiptEvent>> = {};

    for (const wit of state.b) {
      const client = await this.getClient(wit);

      const response = await client.getReceipt(message);
      await this.#store.save(response);

      receipts[wit] = response;

      for (const receipt of response.attachments.receipts) {
        const index = state.b.indexOf(receipt.backer);
        const wig = cesr.decodeMatter(receipt.signature);

        message.attachments.wigs.push(
          cesr.encodeIndexer({
            code: getIndexedCode(wig.code),
            index,
            raw: wig.raw,
          }),
        );
      }
    }

    for (const wit of state.b) {
      const client = await this.getClient(wit);

      for (const [other, receipt] of Object.entries(receipts)) {
        if (other === wit) {
          continue;
        }

        await client.sendMessage(receipt);
      }
    }
  }

  async state(said: string): Promise<KeyState> {
    if (!said || typeof said !== "string") {
      throw new Error(`said must be a string, got ${said}`);
    }

    const result = await this.#store.state(said);

    if (!result) {
      throw new Error(`No state found for said ${said}`);
    }

    return result;
  }

  async listEvents(id: string): Promise<KeyEventMessage[]> {
    return this.#store.list(id);
  }

  async sendCredentialArficats(credential: CredentialEvent, recipient: string): Promise<void> {
    const client = await this.getClient(recipient);
    const state = await this.state(credential.i);

    if (credential.e) {
      for (const [, edge] of Object.entries(credential.e)) {
        if (typeof edge === "object" && "n" in edge && typeof edge.n === "string") {
          const source = await this.store.get(edge.n);

          if (source && source.event.v.startsWith("ACDC")) {
            await this.sendCredentialArficats(source.event as CredentialEvent, recipient);
            if (source.event.i && source.attachments.source) {
              await this.forward(client, {
                message: source,
                recipient: recipient,
                sender: await this.state(source.event.i),
                topic: "credential",
              });
            }
          }
        }
      }
    }

    // Introduce sender to mailbox
    for (const event of await this.#store.list(state.i)) {
      if ("t" in event.event) {
        await client.sendMessage(event);
      }
    }

    // Introduce sender to recipient
    for (const event of await this.#store.list(state.i)) {
      if ("t" in event.event) {
        await this.forward(client, {
          message: event,
          recipient: recipient,
          sender: state,
          topic: "credential",
        });
      }
    }

    // Introduce registry to recipient
    for (const event of await this.#store.list(credential.ri)) {
      if (!event.attachments.source) {
        throw new Error("No source seal found for registry");
      }

      if (!event.attachments.sigs) {
        throw new Error("No signatures found for registry");
      }

      await this.forward(client, {
        message: event,
        recipient,
        sender: state,
        topic: "credential",
      });
    }

    // Introduce transaction to recipient
    for (const event of await this.#store.list(credential.d)) {
      if (!event.attachments.source) {
        throw new Error("No source seal found for credential");
      }

      if (!event.attachments.sigs) {
        throw new Error("No signatures found credential");
      }

      await this.forward(client, {
        message: event,
        recipient,
        sender: state,
        topic: "credential",
      });
    }
  }

  async grant(args: IpexGrantArgs): Promise<void> {
    const state = await this.state(args.credential.i);
    const [registry] = (await this.listEvents(args.credential.ri)) as KeyEventMessage<RegistryInceptEvent>[];

    if (!registry) {
      throw new Error(`Registry not found for said ${args.credential.ri}`);
    }

    const recipient = args.recipient || args.credential.a.i;
    if (!recipient) {
      throw new Error(`No recipient specified and the credential has no issuee`);
    }

    const client = await this.getClient(recipient);

    const transactions = await this.#store.list(args.credential.d);
    const [iss] = transactions as KeyEventMessage<IssueEvent>[];

    if (!iss) {
      throw new Error(`No issuance found for said ${args.credential.d}`);
    }

    if (!iss.attachments.source) {
      throw new Error(`No source seal found for issuance ${iss.event.d}`);
    }

    const anchor = (await this.#store.get(iss.attachments.source.d)) as KeyEventMessage<InteractEvent> | null;

    if (!anchor) {
      throw new Error(`No anchor found for issuance ${iss.event.d}`);
    }

    if (!anchor.attachments.sigs || anchor.attachments.sigs.length === 0) {
      throw new Error(`No signatures found for anchor event ${anchor.event.i}`);
    }

    const event = keri.exchange({
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
        iss: iss.event,
        anc: anchor.event,
      },
    });

    const attachments = new Attachments({
      seal: { i: state.i, s: state.ee.s, d: state.ee.d },
      sigs: await this.sign(event, state.k),
      nested: {
        "-e-acdc": {
          source: {
            i: iss.event.i,
            s: iss.event.s,
            d: iss.event.d,
          },
        },
        "-e-iss": {
          source: {
            // i: iss.attachments.source.i,
            s: iss.attachments.source.s,
            d: iss.attachments.source.d,
          },
          grouped: true,
        },
        "-e-anc": anchor.attachments,
      },
    });

    const message = new KeyEventMessage(event, attachments);

    await this.forward(client, {
      message: message,
      recipient,
      sender: state,
      topic: "credential",
      timestamp: args.timestamp,
    });
  }

  async forward(client: Client, args: ForwardArgs): Promise<void> {
    if (client.role !== "mailbox" && client.role !== "witness") {
      await client.sendMessage(args.message);
      return;
    }

    const seal: KeyEventSeal = {
      i: args.sender.i,
      s: args.sender.ee.s,
      d: args.sender.ee.d,
    };

    const fwd = keri.exchange({
      i: args.sender.i,
      r: "/fwd",
      dt: args.timestamp,
      // rp: args.recipient,
      q: { pre: args.recipient, topic: args.topic },
      a: {},
      e: {
        evt: args.message.event,
      },
    });

    const fwdsigs = await this.sign(fwd, args.sender.k);
    const message = new KeyEventMessage(fwd, {
      sigs: fwdsigs,
      seal: seal,
      nested: {
        "-e-evt": {
          sigs: args.message.attachments.sigs,
          seal: args.message.attachments.seal,
          nested: args.message.attachments.nested,
          source: args.message.attachments.source,
          firstSeen: args.message.attachments.firstSeen,
          receipts: args.message.attachments.receipts,
          grouped: false,
        },
      },
    });

    await client.sendMessage(message);
  }

  async sign(event: Record<string, unknown>, keys: string[]): Promise<string[]> {
    const encoder = new TextEncoder();
    const payload = encoder.encode(JSON.stringify(event));
    const sigs = await Promise.all(keys.map((key, idx) => this.#keyManager.sign(key, payload, idx)));
    return sigs;
  }
}
