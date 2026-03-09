import { PassphraseEncrypter, type Encrypter } from "./encrypt.ts";
import {
  keri,
  sign,
  KeyEventLog,
  Message,
  Attachments,
  MailboxClient,
  submitToWitnesses,
  resolveEndRole,
  resolveLocation,
  type CredentialBody,
  type Endpoint,
  type InceptEvent,
  type InteractEvent,
  type RotateEvent,
  type KeyEventBody,
  type KeyEvent,
  type RegistryInceptEvent,
  type IssueEvent,
  type ReplyEvent,
  type RevokeEvent,
  type KeyState,
  type ExchangeEvent,
} from "#keri/core";
import { cesr, Matter, parse } from "cesr";
import { decodeBase64Url, encodeBase64Url } from "cesr/__unstable__";

export interface ControllerStorage {
  saveMessage(message: Message): void;

  // Key storage
  saveKey(publicKey: string, digest: string, encryptedPrivKey: string): void;
  getKey(publicKey: string): string;
  getPublicKeyByDigest(digest: string): string;

  // Event queries
  getReplies(filter?: { route?: string; eid?: string; cid?: string }): Generator<Message<ReplyEvent>>;
  getKeyEvents(prefix: string): Generator<KeyEvent>;
  getCredentialEvents(id: string): Generator<Message<IssueEvent | RevokeEvent>>;
  getRegistry(id: string): Message<RegistryInceptEvent> | null;
  getRegistriesByOwner(owner: string): Generator<Message<RegistryInceptEvent>>;
  getCredential(id: string): CredentialBody | null;
  getCredentialsByRegistry(registryId: string): CredentialBody[];

  // Mailbox cursor
  getMailboxOffset(prefix: string, topic: string): number;
  saveMailboxOffset(prefix: string, topic: string, offset: number): void;
}

export interface ForwardArgs {
  sender: string;
  recipient: string;
  topic: string;
  message: Message;
  timestamp?: string;
}

export interface ControllerDeps {
  storage: ControllerStorage;
  encrypter?: Encrypter;
  passphrase?: string;
}

export interface ReplyArgs {
  id: string;
  route: string;
  record: Record<string, unknown>;
}

export interface InceptArgs {
  wits?: string[];
  toad?: number;
}

export interface InceptResult {
  id: string;
  event: InceptEvent;
}

export interface AnchorResult {
  id: string;
  event: InteractEvent;
}

export interface RotateResult {
  id: string;
  event: RotateEvent;
}

export interface RotateArgs {
  data?: Record<string, unknown>;
}

export interface AnchorArgs {
  data?: Record<string, unknown>;
}

export interface CreateCredentialArgs {
  registryId: string;
  schemaId: string;
  holder: string;
  salt?: string;
  timestamp?: Date;
  data?: Record<string, unknown>;
  rules?: Record<string, unknown>;
  edges?: Record<string, unknown>;
}

export interface IpexGrantArgs {
  credential: CredentialBody;
  recipient?: string;
  timestamp?: string;
}

export class Controller {
  #storage: ControllerStorage;
  #encrypter: Encrypter;

  constructor(deps: ControllerDeps) {
    this.#storage = deps.storage;
    this.#encrypter = deps.encrypter ?? new PassphraseEncrypter(deps.passphrase ?? "default-passphrase");
  }

  private async generateKey(): Promise<string> {
    const key = keri.utils.generateKeyPair();
    const encrypted = await this.#encrypter.encrypt(key.privateKey);
    this.#storage.saveKey(key.publicKey, key.publicKeyDigest, encodeBase64Url(encrypted));
    return key.publicKey;
  }

  private async signWithKey(publicKey: string, raw: Uint8Array): Promise<string> {
    const encoded = this.#storage.getKey(publicKey);
    const encrypted = decodeBase64Url(encoded);
    const privateKey = await this.#encrypter.decrypt(encrypted);
    return sign(raw, { key: privateKey });
  }

  async introduce(oobi: string): Promise<KeyState> {
    const response = await fetch(oobi);

    if (!response.ok) {
      throw new Error(`Failed to fetch oobi: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error(`No body in response`);
    }

    let log = KeyEventLog.empty();

    for await (const message of parse(response.body)) {
      switch (message.body.t) {
        case "dip":
        case "icp":
        case "rot":
        case "ixn": {
          log = log.append(message as Message<KeyEventBody>);
          await this.processMessage(message);
          break;
        }
        case "rpy": {
          await this.processMessage(new Message(message.body as ReplyEvent));
          break;
        }
      }
    }

    return log.state;
  }

  async loadEventLog(id: string): Promise<KeyEventLog> {
    const log = KeyEventLog.from(this.#storage.getKeyEvents(id));

    if (log.events.length === 0) {
      throw new Error(`State for id ${id} not found`);
    }

    return log;
  }

  resolveEndpoint(aid: string, role = "controller"): Endpoint {
    const endRole = resolveEndRole(this.#storage.getReplies({ cid: aid, route: "/end/role/add" }), aid, role);
    if (!endRole) {
      throw new Error(`Could not find end role '${role}' for aid '${aid}'`);
    }

    const location = resolveLocation(this.#storage.getReplies({ eid: endRole.eid, route: "/loc/scheme" }), endRole.eid);

    if (!location) {
      throw new Error(`No valid location found for aid ${aid}`);
    }

    return {
      aid,
      url: location.url,
      scheme: location.scheme,
      role: endRole.role,
    };
  }

  async sign(raw: Uint8Array, keys: string[]): Promise<string[]> {
    return Promise.all(
      keys.map(async (key, idx) => {
        const sig = await this.signWithKey(key, raw);
        return cesr.index(Matter.parse(sig), idx).text();
      }),
    );
  }

  async incept(args: InceptArgs = {}): Promise<InceptResult> {
    const publicKey = await this.generateKey();
    const nextPublicKey = await this.generateKey();
    const nextPublicKeyDigest = keri.utils.digest(nextPublicKey);

    const event = keri.incept({
      signingKeys: [publicKey],
      nextKeys: [nextPublicKeyDigest],
      wits: args.wits ?? [],
      toad: args.toad,
    });

    await this.commit(KeyEventLog.empty(), event);

    return {
      id: (event.body as InceptEvent).i,
      event: event.body as InceptEvent,
    };
  }

  async processMessage(message: Message): Promise<void> {
    if (message.version.protocol === "ACDC") {
      // TODO: verify ACDC credential SAID and anchors in TEL or KEL
      this.#storage.saveMessage(message);
      return;
    }

    switch (message.body.t) {
      case "icp":
      case "rot":
      case "ixn": {
        const body = message.body as KeyEventBody;
        const log = KeyEventLog.from(this.#storage.getKeyEvents(body.i));

        // TODO: Detect duplicituous key events
        if (!log.events.find((event) => event.body.d === message.body.d)) {
          log.append(message as Message<KeyEventBody>); // throws if verification fails
          this.#storage.saveMessage(message);
        }
        break;
      }
      case "vcp":
      case "iss":
      case "rev":
        // TODO: verify is anchored to a valid ixn in the issuer's KEL
        this.#storage.saveMessage(message);
        break;
      case "rpy":
        // TODO: Verify that is signed by the controller
        this.#storage.saveMessage(message);
        break;
      default:
        // TODO: Handle other message types
        // this.#storage.saveMessage(message);
        break;
    }
  }

  async commit(log: KeyEventLog, event: KeyEvent): Promise<void> {
    const signingKeys = event.body.t === "icp" ? (event.body as InceptEvent).k : log.state.signingKeys;
    const backers = event.body.t === "icp" ? ((event.body as InceptEvent).b ?? []) : (log.state.backers ?? []);
    const sigs = await this.sign(event.raw, signingKeys);
    event.attachments.ControllerIdxSigs.push(...sigs);
    const endpoints = await Promise.all(backers.map((wit) => this.resolveEndpoint(wit)));
    const wigs = await submitToWitnesses(event, endpoints);
    event.attachments.WitnessIdxSigs.push(...wigs);
    await this.processMessage(event);
  }

  async anchor(id: string, anchor: AnchorArgs): Promise<AnchorResult> {
    const log = await this.loadEventLog(id);
    const event = keri.interact(log.state, { data: anchor.data });

    await this.commit(log, event);

    return {
      id: (event.body as InteractEvent).i,
      event: event.body as InteractEvent,
    };
  }

  async rotate(id: string, args: RotateArgs): Promise<RotateResult> {
    const log = await this.loadEventLog(id);
    const state = log.state;
    const publicKeys = await Promise.all(
      state.nextKeyDigests.map((digest) => this.#storage.getPublicKeyByDigest(digest)),
    );
    const nextPublicKey = await this.generateKey();
    const nextPublicKeyDigest = keri.utils.digest(nextPublicKey);

    const event = keri.rotate(state, {
      signingKeys: publicKeys,
      nextKeyDigests: [nextPublicKeyDigest],
      data: args.data,
    });

    await this.commit(log, event);

    return {
      id: (event.body as RotateEvent).i,
      event: event.body as RotateEvent,
    };
  }

  /**
   * Creates and stores a signed reply message and submits to all witnesses.
   */
  async reply(args: ReplyArgs): Promise<void> {
    const log = await this.loadEventLog(args.id);
    const state = log.state;

    const rpy = keri.reply({
      r: args.route,
      a: args.record,
    });

    const sigs = await this.sign(rpy.raw, state.signingKeys);
    rpy.attachments.TransIdxSigGroups.push({
      snu: state.lastEstablishment.s,
      digest: state.lastEstablishment.d,
      prefix: state.identifier,
      ControllerIdxSigs: sigs,
    });

    await this.processMessage(rpy);

    for (const wit of state.backers) {
      const endpoint = this.resolveEndpoint(wit, "controller");
      const client = new MailboxClient({
        id: wit,
        url: endpoint.url,
      });

      await client.sendMessage(rpy);
    }
  }

  async forward(args: ForwardArgs): Promise<void> {
    const endpoint = this.resolveEndpoint(args.recipient, "mailbox");
    const client = new MailboxClient({
      id: endpoint.aid,
      url: endpoint.url,
    });
    const log = await this.loadEventLog(args.sender);
    const state = log.state;

    const hasAttachments = args.message.attachments.frames().length > 1;
    if (!hasAttachments) {
      args.message.attachments.TransIdxSigGroups.push({
        snu: state.lastEstablishment.s,
        digest: state.lastEstablishment.d,
        prefix: args.sender,
        ControllerIdxSigs: await this.sign(args.message.raw, state.signingKeys),
      });
    }

    const fwd = keri.exchange({
      sender: args.sender,
      route: "/fwd",
      timestamp: args.timestamp,
      // rp: args.recipient,
      query: { pre: args.recipient, topic: args.topic },
      anchor: {},
      embeds: {
        evt: args.message,
      },
    });

    const fwdsigs = await this.sign(fwd.raw, state.signingKeys);
    fwd.attachments = {
      TransIdxSigGroups: [
        {
          prefix: args.sender,
          ControllerIdxSigs: fwdsigs,
          snu: state.lastEstablishment.s,
          digest: state.lastEstablishment.d,
        },
      ],
      PathedMaterialCouples: fwd.attachments.PathedMaterialCouples.map((couple) => ({
        ...couple,
        grouped: false,
      })),
    };

    await client.sendMessage(fwd);
  }

  async createRegistry(owner: string): Promise<RegistryInceptEvent> {
    const log = await this.loadEventLog(owner);

    const vcp = keri.registry({
      ii: owner,
    });

    const anchor = await this.anchor(owner, {
      data: {
        d: vcp.body.d,
        s: vcp.body.s,
        i: vcp.body.i,
      },
    });

    const seal = { digest: anchor.event.d, snu: anchor.event.s };
    vcp.attachments.SealSourceCouples.push(seal);

    const state = log.state;
    for (const wit of state.backers) {
      const endpoint = this.resolveEndpoint(wit, "controller");
      const client = new MailboxClient({
        id: wit,
        url: endpoint.url,
      });

      await client.sendMessage(vcp);
    }

    await this.processMessage(vcp);

    return vcp.body;
  }

  async listRegistries(owner: string): Promise<RegistryInceptEvent[]> {
    return Array.from(this.#storage.getRegistriesByOwner(owner)).map((message) => message.body);
  }

  async createCredential(args: CreateCredentialArgs): Promise<CredentialBody> {
    const registry = this.#storage.getRegistry(args.registryId);

    if (!registry) {
      throw new Error(`Registry ${args.registryId} not found`);
    }

    const log = await this.loadEventLog(registry.body.ii);
    const state = log.state;

    const credential = keri.credential({
      i: state.identifier,
      ri: registry.body.i,
      s: args.schemaId,
      u: args.salt,
      a: {
        i: args.holder,
        dt: keri.utils.formatDate(args.timestamp ?? new Date()),
        ...args.data,
      },
      r: args.rules,
      e: args.edges,
    });

    await this.processMessage(credential);

    return credential.body;
  }

  async getCredential(id: string): Promise<CredentialBody | null> {
    return this.#storage.getCredential(id);
  }

  async listCredentials(registryId: string): Promise<CredentialBody[]> {
    return this.#storage.getCredentialsByRegistry(registryId);
  }

  async issueCredential(credential: CredentialBody): Promise<void> {
    const log = await this.loadEventLog(credential.i);

    const iss = keri.issue({
      i: credential.d,
      ri: credential.ri,
      dt: credential.a.dt,
    });

    const anchor = await this.anchor(credential.i, {
      data: {
        d: iss.body.d,
        s: iss.body.s,
        i: iss.body.i,
      },
    });

    const seal = { digest: anchor.event.d, snu: anchor.event.s };
    iss.attachments.SealSourceCouples.push(seal);

    const state = log.state;
    for (const wit of state.backers) {
      const endpoint = this.resolveEndpoint(wit, "controller");
      const client = new MailboxClient({
        id: wit,
        url: endpoint.url,
      });

      await client.sendMessage(iss);
    }

    await this.processMessage(iss);
  }

  private getIssueEvent(credentialSaid: string): Message<IssueEvent> {
    const [iss] = [...this.#storage.getCredentialEvents(credentialSaid)] as Message<IssueEvent>[];

    if (!iss) {
      throw new Error(`No issuance found for said ${credentialSaid}`);
    }

    return iss;
  }

  private getAnchorFromSeal(aid: string, digest: string): Message<KeyEventBody> {
    const log = KeyEventLog.from(this.#storage.getKeyEvents(aid) as Iterable<Message<KeyEventBody>>);
    const anchor = log.events.find((message) => message.body.d === digest);

    if (!anchor) {
      throw new Error(`No anchor found for digest ${digest}`);
    }

    return anchor;
  }

  private buildCredentialMessage(credential: CredentialBody): Message<CredentialBody> | null {
    const [iss] = [...this.#storage.getCredentialEvents(credential.d)] as Message<IssueEvent>[];

    if (!iss) {
      return null;
    }

    return new Message(credential, {
      SealSourceTriples: [
        {
          prefix: iss.body.i,
          snu: iss.body.s,
          digest: iss.body.d,
        },
      ],
    });
  }

  async sendCredentialArtifacts(credential: CredentialBody, recipient: string): Promise<void> {
    const log = await this.loadEventLog(credential.i);
    const state = log.state;

    if (credential.e) {
      for (const [, edge] of Object.entries(credential.e)) {
        if (typeof edge === "object" && edge !== null && "n" in edge && typeof edge.n === "string") {
          const source = this.#storage.getCredential(edge.n);

          if (!source) {
            throw new Error(`No source found for edge ${edge.n}`);
          }

          await this.sendCredentialArtifacts(source, recipient);

          const sourceMessage = this.buildCredentialMessage(source);

          if (sourceMessage) {
            await this.forward({
              message: sourceMessage,
              recipient: recipient,
              sender: source.i,
              topic: "credential",
            });
          }
        }
      }
    }

    const endpoint = this.resolveEndpoint(recipient, "mailbox");
    const mailbox = new MailboxClient({
      id: endpoint.aid,
      url: endpoint.url,
    });

    for (const event of log.events) {
      await mailbox.sendMessage(event);
    }

    for (const event of log.events) {
      await this.forward({
        message: event,
        recipient,
        sender: state.identifier,
        topic: "credential",
      });
    }

    const registryMessage = this.#storage.getRegistry(credential.ri);
    if (!registryMessage) {
      throw new Error(`Registry with id ${credential.ri} not found`);
    }

    if (
      !registryMessage.attachments.SealSourceCouples.length &&
      !registryMessage.attachments.SealSourceTriples.length
    ) {
      throw new Error("No seal found for registry");
    }

    await this.forward({
      message: registryMessage,
      recipient,
      sender: state.identifier,
      topic: "credential",
    });

    for (const message of this.#storage.getCredentialEvents(credential.d)) {
      if (!message.attachments.SealSourceCouples.length && !message.attachments.SealSourceTriples.length) {
        throw new Error("No seal found for issuance");
      }

      await this.forward({
        message,
        recipient,
        sender: state.identifier,
        topic: "credential",
      });
    }
  }

  async grant(args: IpexGrantArgs): Promise<void> {
    const log = await this.loadEventLog(args.credential.i);
    const state = log.state;
    const registry = this.#storage.getRegistry(args.credential.ri);

    if (!registry) {
      throw new Error(`Registry not found for said ${args.credential.ri}`);
    }

    const issuee = args.credential.a.i;
    const recipient = args.recipient || (typeof issuee === "string" && issuee ? issuee : undefined);

    if (!recipient) {
      throw new Error("No recipient specified and the credential has no issuee");
    }

    const iss = this.getIssueEvent(args.credential.d);
    const anchorSeal = iss.attachments.SealSourceCouples[0] || iss.attachments.SealSourceTriples[0];

    if (!anchorSeal) {
      throw new Error(`No seal found for issuance ${iss.body.d}`);
    }

    const anchor = this.getAnchorFromSeal(args.credential.i, anchorSeal.digest);

    const grant = keri.exchange({
      sender: state.identifier,
      route: "/ipex/grant",
      timestamp: args.timestamp,
      query: {},
      anchor: {
        m: "",
        i: recipient,
      },
      embeds: {
        acdc: new Message(args.credential, {
          SealSourceTriples: [
            {
              prefix: iss.body.i,
              snu: iss.body.s,
              digest: iss.body.d,
            },
          ],
        }),
        iss: new Message(iss.body, {
          SealSourceCouples: [
            {
              digest: anchor.body.d,
              snu: anchor.body.s as string,
            },
          ],
        }),
        anc: new Message(anchor.body, {
          ControllerIdxSigs: anchor.attachments.ControllerIdxSigs,
          WitnessIdxSigs: anchor.attachments.WitnessIdxSigs,
        }),
      },
    });

    const grantsigs = await this.sign(grant.raw, state.signingKeys);
    grant.attachments.TransIdxSigGroups.push({
      snu: state.lastEstablishment.s,
      digest: state.lastEstablishment.d,
      prefix: state.identifier,
      ControllerIdxSigs: grantsigs,
    });

    await this.forward({
      message: grant,
      recipient,
      sender: state.identifier,
      topic: "credential",
      timestamp: args.timestamp,
    });
  }

  async query(id: string, topic: string): Promise<Message[]> {
    const log = await this.loadEventLog(id);
    const state = log.state;
    const endpoint = this.resolveEndpoint(id, "mailbox");
    const client = new MailboxClient({ id: endpoint.aid, url: endpoint.url });

    const offset = this.#storage.getMailboxOffset(id, topic);

    const queryMessage = keri.query({
      r: "mbx",
      q: {
        src: endpoint.aid,
        i: id,
        topics: { [`/${topic}`]: offset },
      },
    });

    queryMessage.attachments = {
      TransLastIdxSigGroups: [
        {
          prefix: id,
          ControllerIdxSigs: await this.sign(queryMessage.raw, state.signingKeys),
        },
      ],
    };

    const result = await client.sendMessage(queryMessage, AbortSignal.timeout(10000));

    for (const incoming of result) {
      this.#storage.saveMessage(incoming);
    }

    this.#storage.saveMailboxOffset(id, topic, offset + result.length);

    return result;
  }

  async receiveGrants(holderId: string): Promise<CredentialBody[]> {
    const messages = await this.query(holderId, "credential");
    const credentials: CredentialBody[] = [];

    for (const message of messages) {
      const body = message.body as ExchangeEvent;
      if (body.t !== "exn" || body.r !== "/ipex/grant") {
        continue;
      }

      const acdcBody = body.e?.acdc as CredentialBody | undefined;
      const issBody = body.e?.iss as IssueEvent | undefined;

      if (!acdcBody || !issBody) {
        throw new Error("Invalid grant message: missing acdc or iss embed");
      }

      const acdcCouple = message.attachments.PathedMaterialCouples.find((c) => c.path === "-e-acdc");
      const issCouple = message.attachments.PathedMaterialCouples.find((c) => c.path === "-e-iss");

      this.#storage.saveMessage(new Message(acdcBody, acdcCouple?.attachments ?? new Attachments()));
      if (issBody) {
        this.#storage.saveMessage(new Message(issBody, issCouple?.attachments ?? new Attachments()));
      }
      credentials.push(acdcBody);
    }

    return credentials;
  }

  async export(id: string): Promise<Message[]> {
    const log = await this.loadEventLog(id);
    return log.events;
  }
}
