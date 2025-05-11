import {
  cesr,
  CountCode_10,
  encodeAttachmentsV1,
  encodeBase64Int,
  encodeCounter,
  encodeString,
  IndexCode,
  MatterCode,
} from "cesr/__unstable__";
import {
  ControllerEventStore,
  type KeyValueStorage,
  type KeyEventMessage,
  type KeyEventReceipt,
  type KeyEventSeal,
  type KeyState,
  type LocationRecord,
} from "./events/event-store.ts";
import type { Key, KeyStore } from "./keystore/keystore.ts";
import {
  keri,
  type KeyEvent,
  type InteractEvent,
  type CredentialEvent,
  type RegistryInceptEvent,
  type IssueEvent,
  formatDate,
} from "./events/events.ts";
import { Client, parseKeyEvents } from "./client.ts";

export interface ControllerDeps {
  keystore: KeyStore;
  storage: KeyValueStorage;
}

export interface IpexGrantArgs {
  credential: CredentialEvent;
  recipient?: string;
  timestamp?: string;
}

export interface ForwardArgs {
  event: KeyEvent;
  sender: KeyState;
  topic: string;
  recipient: string;
  attachment?: string;
  timestamp?: string;
}

function encodeHexNumber(num: string) {
  return `${MatterCode.Salt_128}${encodeBase64Int(parseInt(num, 16), 22)}`;
}

function serializeSignatures(sigs: string[], seal?: KeyEventSeal): string {
  const result: string[] = [];

  if (sigs && sigs.length > 0) {
    if (seal && seal.i && seal.s && seal.d) {
      result.push(
        encodeCounter({
          code: CountCode_10.TransIdxSigGroups,
          count: 1,
        }),
      );

      result.push(seal.i);
      result.push(encodeHexNumber(seal.s));
      result.push(seal.d);
    }

    result.push(encodeCounter({ code: CountCode_10.ControllerIdxSigs, count: sigs.length }));
    result.push(...sigs);
  }

  return result.join("");
}

function serializeWitnessSignatures(receipts: KeyEventReceipt[], backers: string[]): string {
  const result: string[] = [];

  if (receipts.length > 0) {
    result.push(encodeCounter({ code: CountCode_10.WitnessIdxSigs, count: receipts.length }));

    for (const sig of receipts) {
      const signature = cesr.decodeMatter(sig.signature);
      const index = backers.indexOf(sig.backer);
      if (index === -1) {
        throw new Error(`Unknown backer ${sig.backer}`);
      }

      result.push(
        cesr.encodeIndexer({
          code: getIndexedCode(signature.code),
          raw: signature.raw,
          index: index,
        }),
      );
    }
  }

  return result.join("");
}

function serializeReceipts(receipts: KeyEventReceipt[]): string {
  const result: string[] = [];

  if (receipts.length > 0) {
    result.push(encodeCounter({ code: CountCode_10.NonTransReceiptCouples, count: receipts.length }));
    result.push(...receipts.map((receipt) => receipt.backer + receipt.signature));
  }

  return result.join("");
}

function serializePathedGroup(path: string[], attachments: string[]) {
  const result: string[] = [];

  result.push(encodeString(`-${path.join("-")}`));
  result.push(...attachments);

  return (
    encodeCounter({
      code: CountCode_10.PathedMaterialCouples,
      count: result.join("").length / 4,
    }) + result.join("")
  );
}

function serializeAttachments(attachments: string[]): string {
  const result = attachments.join("");
  return `${encodeAttachmentsV1(result.length / 4)}${result}`;
}

export function serializeEventSeal(seal: KeyEventSeal) {
  return [
    encodeCounter({ code: CountCode_10.SealSourceTriples, count: 1 }),
    seal.i,
    encodeHexNumber(seal.s),
    seal.d,
  ].join("");
}

function serializeDigestSeal(seal: KeyEventSeal) {
  return [encodeCounter({ code: CountCode_10.SealSourceCouples, count: 1 }), encodeHexNumber(seal.s), seal.d].join("");
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
  #keystore: KeyStore;
  #store: ControllerEventStore;

  get store() {
    return this.#store;
  }

  constructor(deps: ControllerDeps) {
    this.#store = new ControllerEventStore(deps.storage);
    this.#keystore = deps.keystore;
  }

  async createIdentifier(args: InceptArgs = {}): Promise<KeyState> {
    const keys = args.keys ?? [await this.#keystore.incept()];

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

    await this.#store.save({
      event,
      signatures: sigs,
    });

    await this.submit(event, sigs);

    return await this.#store.state(event.i);
  }

  async interact(args: InteractArgs): Promise<InteractEvent> {
    const state = await this.state(args.aid);

    const sn = (parseInt(state.s ?? "0", 16) + 1).toString(16);
    const event = keri.interact({ i: state.i, p: state.d, s: sn, a: [args.data] });

    const sigs = await this.sign(event, state.k);

    await this.#store.save({
      event,
      signatures: sigs,
    });

    await this.submit(event, sigs);

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

    for (const wit of state.b) {
      const endpoint = await this.getClient(wit);

      const attachment = serializeAttachments([serializeDigestSeal(anchor)]);

      await endpoint.sendMessage({ event: registry, attachment });
    }

    await this.#store.save({
      event: registry,
      seal: {
        i: anchor.i,
        s: anchor.s,
        d: anchor.d,
      },
    });

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

    for (const wit of state.b) {
      const client = await this.getClient(wit);
      const attachment = serializeAttachments([serializeDigestSeal(anchor)]);
      await client.sendMessage({ event: iss, attachment });
    }

    await this.#store.save({
      event: acdc as unknown as KeyEvent,
      seal: iss,
    });

    await this.#store.save({
      event: iss,
      seal: anchor,
    });

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

    for await (const event of parseKeyEvents(response.body)) {
      await this.#store.save(event);
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

  async submit(event: KeyEvent, signatures: string[]): Promise<void> {
    if (!event || !("i" in event && typeof event.i === "string")) {
      throw new Error("No such event");
    }

    const state = await this.state(event.i);
    const receipts: Record<string, KeyEventMessage> = {};

    for (const wit of state.b) {
      const client = await this.getClient(wit);

      const attachment = serializeAttachments([serializeSignatures(signatures)]);
      const response = await client.getReceipt({ event, attachment });
      await this.#store.save(response);

      receipts[wit] = response;
    }

    for (const wit of state.b) {
      const client = await this.getClient(wit);

      for (const [other, receipt] of Object.entries(receipts)) {
        if (other === wit) {
          continue;
        }

        const attachment = serializeAttachments([serializeReceipts(receipt.receipts)]);
        await client.sendMessage({ event: receipt.event, attachment });
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

  async list(id: string): Promise<KeyEventMessage[]> {
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
            if (source.seal && source.event.i) {
              await this.forward(client, {
                event: source.event,
                recipient: recipient,
                sender: await this.state(source.event.i),
                topic: "credential",
                attachment: serializeEventSeal(source.seal),
              });
            }
          }
        }
      }
    }

    // Introduce sender to mailbox
    for (const event of await this.#store.list(state.i)) {
      if ("t" in event.event) {
        await client.sendMessage({
          event: event.event,
          attachment: serializeAttachments([
            serializeSignatures(event.signatures),
            serializeWitnessSignatures(event.receipts, state.b),
            encodeCounter({
              code: CountCode_10.FirstSeenReplayCouples,
              count: 1,
            }),
            encodeHexNumber(event.event.s ?? "0"),
            cesr.encodeDate(event.timestamp),
          ]),
        });
      }
    }

    // Introduce sender to recipient
    for (const event of await this.#store.list(state.i)) {
      if ("t" in event.event) {
        await this.forward(client, {
          event: event.event,
          recipient: recipient,
          sender: state,
          topic: "credential",
          attachment: serializeAttachments([
            serializeSignatures(event.signatures),
            serializeWitnessSignatures(event.receipts, state.b),
            encodeCounter({
              code: CountCode_10.FirstSeenReplayCouples,
              count: 1,
            }),
            encodeHexNumber(event.event.s ?? "0"),
            cesr.encodeDate(event.timestamp),
          ]),
        });
      }
    }

    // Introduce registry to recipient
    for (const event of await this.#store.list(credential.ri)) {
      if (!event.seal) {
        throw new Error("No seal found for registry");
      }

      await this.forward(client, {
        event: event.event,
        recipient,
        sender: state,
        topic: "credential",
        attachment: serializeAttachments([serializeDigestSeal(event.seal)]),
      });
    }

    // Introduce transaction to recipient
    for (const event of await this.#store.list(credential.d)) {
      if (!event.seal) {
        throw new Error("No seal found for issuance");
      }

      await this.forward(client, {
        event: event.event,
        recipient,
        sender: state,
        topic: "credential",
        attachment: serializeAttachments([serializeDigestSeal(event.seal)]),
      });
    }
  }

  async grant(args: IpexGrantArgs): Promise<void> {
    const state = await this.state(args.credential.i);
    const [registry] = (await this.list(args.credential.ri)) as KeyEventMessage<RegistryInceptEvent>[];

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
    const [iss] = transactions as KeyEventMessage<IssueEvent>[];

    if (!iss) {
      throw new Error(`No issuance found for said ${args.credential.d}`);
    }

    if (!iss.seal) {
      throw new Error(`No seal found for issuance ${iss.event.d}`);
    }

    const anchor = await this.#store.get(iss.seal.d);

    if (!anchor) {
      throw new Error(`No anchor found for issuance ${iss.event.d}`);
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
        iss: iss.event,
        anc: anchor.event,
      },
    });

    const grantsigs = await this.sign(grant, state.k);

    await this.forward(client, {
      event: grant,
      recipient,
      sender: state,
      topic: "credential",
      timestamp: args.timestamp,
      attachment: [
        serializeSignatures(grantsigs, seal),
        serializePathedGroup(["e", "acdc"], [serializeEventSeal(iss.event)]),
        serializePathedGroup(["e", "iss"], [serializeAttachments([serializeDigestSeal(anchor.event as KeyEventSeal)])]),
        serializePathedGroup(
          ["e", "anc"],
          [
            serializeAttachments([
              serializeSignatures(anchor.signatures),
              serializeWitnessSignatures(anchor.receipts, state.b),
              encodeCounter({
                code: CountCode_10.FirstSeenReplayCouples,
                count: 1,
              }),
              encodeHexNumber(anchor.event.s ?? "0"),
              cesr.encodeDate(anchor.timestamp),
            ]),
          ],
        ),
      ].join(""),
    });
  }

  async forward(client: Client, args: ForwardArgs): Promise<void> {
    if (client.role !== "mailbox" && client.role !== "witness") {
      const sigs = await this.sign(args.event, args.sender.k);

      const attachments = [args.attachment ? [args.attachment] : [serializeSignatures(sigs)]].join("");

      await client.sendMessage({ event: args.event, attachment: attachments });
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
        evt: args.event,
      },
    });

    const fwdsigs = await this.sign(fwd, args.sender.k);
    const evtsigs = await this.sign(args.event, args.sender.k);

    const attachments = [
      serializeSignatures(fwdsigs, seal),
      serializePathedGroup(["e", "evt"], args.attachment ? [args.attachment] : [serializeSignatures(evtsigs, seal)]),
    ].join("");

    await client.sendMessage({ event: fwd, attachment: attachments });
  }

  async sign(event: Record<string, unknown>, keys: string[]): Promise<string[]> {
    const encoder = new TextEncoder();
    const payload = encoder.encode(JSON.stringify(event));
    const sigs = await Promise.all(keys.map((key, idx) => this.#keystore.sign(key, payload, idx)));
    return sigs;
  }
}

function getIndexedCode(code: string): string {
  switch (code) {
    case MatterCode.Ed25519_Sig:
      return IndexCode.Ed25519_Sig;
    case MatterCode.Ed448_Sig:
      return IndexCode.Ed448_Sig;
    default:
      throw new Error(`Unsupported indexed signature type: ${code}`);
  }
}
