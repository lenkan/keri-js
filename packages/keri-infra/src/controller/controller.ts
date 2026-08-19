import { encodeText, Indexer, Matter, parse } from "cesr";
import { decodeBase64Url, encodeBase64Url } from "cesr/encoding";
import {
  Credential,
  type CredentialBody,
  type DipEventBody,
  type ExchangeEventBody,
  ed25519Signer,
  formatDate,
  generateKeyPair,
  type InceptEventBody,
  type InteractEventBody,
  type IssueEventBody,
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  type KeyState,
  Message,
  nextKeyDigest,
  type RegistryInceptEventBody,
  type ReplyEventBody,
  type RotateEventBody,
  RoutedEvent,
  type Signer,
  TransactionEvent,
} from "keri";
import { MailboxClient, submitToWitnesses } from "../http/main.ts";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { CredentialStorage, KeyEventStorage, MailboxStorage, PrivateKeyStorage } from "../storage/main.ts";
import { type Encrypter, PassphraseEncrypter } from "./encrypt.ts";
import type { Endpoint } from "./endpoint-discovery.ts";
import { resolveEndRole, resolveLocation } from "./endpoint-discovery.ts";

export type { CredentialStorage, KeyEventStorage, MailboxStorage, PrivateKeyStorage } from "../storage/main.ts";
export type { Encrypter } from "./encrypt.ts";

export type ControllerStorage = KeyEventStorage & PrivateKeyStorage & CredentialStorage & MailboxStorage;

export interface ForwardArgs {
  sender: string;
  recipient: string;
  topic: string;
  message: Message;
  timestamp?: Date;
}

export interface ControllerDeps {
  storage: ControllerStorage;
  encrypter?: Encrypter;
  passphrase?: string;
  fetch?: typeof globalThis.fetch;
  logger?: Logger;
}

export interface ReplyArgs {
  id: string;
  route: string;
  record: Record<string, unknown>;
}

export interface ControllerInceptArgs {
  wits?: string[];
  toad?: number;
}

export interface InceptResult {
  id: string;
  event: InceptEventBody;
}

export interface ControllerDelegatedInceptArgs {
  delegator: string;
  wits?: string[];
  toad?: number;
}

export interface DelegatedInceptResult {
  id: string;
  event: Message<DipEventBody>;
}

export interface AnchorResult {
  id: string;
  event: InteractEventBody;
}

export interface RotateResult {
  id: string;
  event: RotateEventBody;
}

export interface ControllerRotateArgs {
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
  timestamp?: Date;
}

export class Controller {
  #storage: ControllerStorage;
  #encrypter: Encrypter;
  #fetch: typeof globalThis.fetch;
  #log: KeriLogger;

  constructor(deps: ControllerDeps) {
    this.#storage = deps.storage;
    this.#encrypter = deps.encrypter ?? new PassphraseEncrypter(deps.passphrase ?? "default-passphrase");
    this.#fetch = deps.fetch ?? globalThis.fetch;
    this.#log = new KeriLogger(deps.logger);
  }

  private async generateKey(): Promise<string> {
    const key = generateKeyPair();
    if (!key.privateKey || !key.publicKey || !key.publicKeyDigest) {
      throw new Error("Failed to generate key pair");
    }

    const encrypted = await this.#encrypter.encrypt(key.privateKey);
    this.#storage.saveKey(key.publicKey, key.publicKeyDigest, encodeBase64Url(encrypted));
    return key.publicKey;
  }

  /**
   * A {@link Signer} over one stored key. The private key is decrypted per
   * signature and never held on the controller — which is why `Signer.sign` is
   * async.
   */
  signer(publicKey: string): Signer {
    return {
      publicKey,
      sign: async (payload: Uint8Array): Promise<string> => {
        const encoded = this.#storage.getEncryptedPrivateKey(publicKey);
        const privateKey = await this.#encrypter.decrypt(decodeBase64Url(encoded));
        return ed25519Signer(privateKey).sign(payload);
      },
    };
  }

  async introduce(oobi: string): Promise<KeyState> {
    this.#log.debug("introduce: fetching oobi", { oobi });
    const response = await this.#fetch(oobi);

    if (!response.ok) {
      this.#log.warn("introduce: oobi fetch failed", { oobi, status: response.status });
      throw new Error(`Failed to fetch oobi: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      this.#log.warn("introduce: empty response body", { oobi });
      throw new Error(`No body in response`);
    }

    const kelMessages: Message<KeyEventBody>[] = [];
    const otherMessages: Message[] = [];

    for await (const message of parse(response.body)) {
      if (KeyEvent.isKeyEvent(message)) {
        kelMessages.push(message as Message<KeyEventBody>);
      } else if (message.body.t === "rpy") {
        otherMessages.push(new Message(message.body as ReplyEventBody));
      }
    }

    // Validate the full KEL chain (multi-AID + delegator-anchor verification)
    // before persisting any of it. `fromMessages` returns the leaf AID's log.
    const log = KeyEventLog.fromMessages(kelMessages, { allowPartiallyWitnessed: true });

    for (const message of kelMessages) {
      await this.processMessage(message);
    }
    for (const message of otherMessages) {
      await this.processMessage(message);
    }

    this.#log.debug("introduce: complete", {
      aid: log.state.identifier,
      messages: kelMessages.length + otherMessages.length,
    });
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
        const sig = await this.signer(key).sign(raw);
        return encodeText(Indexer.convert(Matter.parse(sig), idx));
      }),
    );
  }

  async incept(args: ControllerInceptArgs = {}): Promise<InceptResult> {
    const publicKey = await this.generateKey();
    const nextPublicKey = await this.generateKey();
    const nextPublicKeyDigest = nextKeyDigest(nextPublicKey);

    const event = KeyEvent.incept({
      signingKeys: [publicKey],
      nextKeyDigests: [nextPublicKeyDigest],
      backers: args.wits ?? [],
      backerThreshold: args.toad,
    });

    const body = event.body as InceptEventBody;
    this.#log.debug("incept: created", { aid: body.i, wits: body.b?.length ?? 0 });
    await this.commit(KeyEventLog.empty(), event);

    return {
      id: body.i,
      event: body,
    };
  }

  /**
   * Builds a delegated inception event (dip) without submitting it to witnesses.
   *
   * The caller must:
   *  1. pass `event.body` (or `{i, s, d}`) to the delegator so it can create
   *     an interaction event anchoring this dip;
   *  2. attach the resulting SealSourceCouple to `event.attachments.SealSourceCouples`;
   *  3. call `controller.commit(KeyEventLog.empty(), event)` to publish.
   *
   * Witnesses won't accept the dip until it carries a SealSourceCouple proving
   * the delegator anchored it, so this method intentionally stops short of
   * submission.
   */
  async delegatedIncept(args: ControllerDelegatedInceptArgs): Promise<DelegatedInceptResult> {
    const publicKey = await this.generateKey();
    const nextPublicKey = await this.generateKey();
    const nextPublicKeyDigest = nextKeyDigest(nextPublicKey);

    const event = KeyEvent.delegatedIncept({
      signingKeys: [publicKey],
      nextKeyDigests: [nextPublicKeyDigest],
      backers: args.wits ?? [],
      backerThreshold: args.toad,
      delegator: args.delegator,
    });

    this.#log.debug("delegatedIncept: created", {
      aid: event.body.i,
      delegator: args.delegator,
      wits: event.body.b?.length ?? 0,
    });

    return {
      id: event.body.i,
      event,
    };
  }

  async processMessage(message: Message): Promise<void> {
    if (message.version.protocol === "ACDC") {
      // TODO: verify ACDC credential SAID and anchors in TEL or KEL, via
      // verifyCredentialSaid / verifyCredential from core/main.ts
      this.#log.debug("processMessage: saving ACDC", { d: message.body.d });
      this.#storage.saveMessage(message);
      return;
    }

    switch (message.body.t) {
      case "icp":
      case "rot":
      case "ixn":
      case "dip":
      case "drt": {
        const body = message.body as KeyEventBody;
        const log = KeyEventLog.from(this.#storage.getKeyEvents(body.i));

        // TODO: Detect duplicituous key events
        if (!log.events.find((event) => event.body.d === message.body.d)) {
          log.append(message as Message<KeyEventBody>); // throws if verification fails
          this.#storage.saveMessage(message);
          this.#log.debug("processMessage: appended key event", { t: body.t, aid: body.i, s: body.s, d: body.d });
        } else {
          this.#log.debug("processMessage: duplicate key event ignored", { t: body.t, aid: body.i, d: body.d });
        }
        break;
      }
      case "vcp":
      case "iss":
      case "rev":
        // TODO: verify is anchored to a valid ixn in the issuer's KEL, via
        // verifyTransactionEventAnchor from core/main.ts
        this.#log.debug("processMessage: saving registry event", { t: message.body.t, d: message.body.d });
        this.#storage.saveMessage(message);
        break;
      case "rpy":
        // TODO: Verify that is signed by the controller
        this.#log.debug("processMessage: saving reply", { d: message.body.d });
        this.#storage.saveMessage(message);
        break;
      default:
        // TODO: Handle other message types
        this.#log.debug("processMessage: ignoring", { t: message.body.t });
        // this.#storage.saveMessage(message);
        break;
    }
  }

  async commit(log: KeyEventLog, event: Message<KeyEventBody>): Promise<void> {
    const body = event.body as KeyEventBody;
    const isInception = body.t === "icp" || body.t === "dip";
    const signingKeys = isInception ? (event.body as InceptEventBody).k : log.state.signingKeys;
    const backers = isInception ? ((event.body as InceptEventBody).b ?? []) : (log.state.backers ?? []);
    const sigs = await this.sign(event.raw, signingKeys);
    event.attachments.ControllerIdxSigs.push(...sigs);
    this.#log.debug("commit: submitting to witnesses", {
      t: body.t,
      aid: body.i,
      s: body.s,
      backers: backers.length,
    });
    const endpoints = await Promise.all(backers.map((wit) => this.resolveEndpoint(wit)));
    const wigs = await submitToWitnesses(event, endpoints, this.#fetch);
    event.attachments.WitnessIdxSigs.push(...wigs);
    this.#log.debug("commit: received witness signatures", { aid: body.i, s: body.s, wigs: wigs.length });
    await this.processMessage(event);
  }

  async anchor(id: string, anchor: AnchorArgs): Promise<AnchorResult> {
    const log = await this.loadEventLog(id);
    const event = KeyEvent.interact(log.state, { data: anchor.data });

    this.#log.debug("anchor: created interaction", { aid: id, s: (event.body as InteractEventBody).s });
    await this.commit(log, event);

    return {
      id: (event.body as InteractEventBody).i,
      event: event.body as InteractEventBody,
    };
  }

  async rotate(id: string, args: ControllerRotateArgs): Promise<RotateResult> {
    const log = await this.loadEventLog(id);
    const state = log.state;
    const publicKeys = await Promise.all(
      state.nextKeyDigests.map((digest) => this.#storage.getPublicKeyByDigest(digest)),
    );
    const nextPublicKey = await this.generateKey();
    const nextPublicKeyDigest = nextKeyDigest(nextPublicKey);

    const event = KeyEvent.rotate(state, {
      signingKeys: publicKeys,
      nextKeyDigests: [nextPublicKeyDigest],
      data: args.data,
    });

    this.#log.debug("rotate: created rotation", { aid: id, s: (event.body as RotateEventBody).s });
    await this.commit(log, event);

    return {
      id: (event.body as RotateEventBody).i,
      event: event.body as RotateEventBody,
    };
  }

  /**
   * Creates and stores a signed reply message and submits to all witnesses.
   */
  async reply(args: ReplyArgs): Promise<void> {
    const log = await this.loadEventLog(args.id);
    const state = log.state;

    const rpy = RoutedEvent.reply({
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

    this.#log.debug("reply: broadcasting", { aid: args.id, route: args.route, witnesses: state.backers.length });
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
    this.#log.debug("forward: dispatching", {
      sender: args.sender,
      recipient: args.recipient,
      topic: args.topic,
    });
    const endpoint = this.resolveEndpoint(args.recipient, "mailbox");
    const client = new MailboxClient({
      id: endpoint.aid,
      url: endpoint.url,
      fetch: this.#fetch,
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

    const fwd = RoutedEvent.exchange({
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

  async createRegistry(owner: string): Promise<RegistryInceptEventBody> {
    const log = await this.loadEventLog(owner);

    const vcp = TransactionEvent.incept({
      ii: owner,
    });

    this.#log.debug("createRegistry: created", { owner, registry: vcp.body.i });

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
        fetch: this.#fetch,
      });

      await client.sendMessage(vcp);
    }

    await this.processMessage(vcp);

    return vcp.body;
  }

  async listRegistries(owner: string): Promise<RegistryInceptEventBody[]> {
    return Array.from(this.#storage.getRegistriesByOwner(owner)).map((message) => message.body);
  }

  async createCredential(args: CreateCredentialArgs): Promise<CredentialBody> {
    const registry = this.#storage.getRegistry(args.registryId);

    if (!registry) {
      this.#log.warn("createCredential: registry not found", { registryId: args.registryId });
      throw new Error(`Registry ${args.registryId} not found`);
    }

    const log = await this.loadEventLog(registry.body.ii);
    const state = log.state;

    const credential = Credential.from({
      i: state.identifier,
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

    this.#log.debug("createCredential: created", {
      d: credential.body.d,
      registry: args.registryId,
      schema: args.schemaId,
      holder: args.holder,
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
    this.#log.debug("issueCredential: issuing", { credential: credential.d, issuer: credential.i });

    const iss = TransactionEvent.issue({
      i: credential.d,
      ri: credential.ri,
      dt: credential.a.dt ? new Date(credential.a.dt) : undefined,
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

  private getIssueEvent(credentialSaid: string): Message<IssueEventBody> {
    const [iss] = [...this.#storage.getCredentialEvents(credentialSaid)] as Message<IssueEventBody>[];

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
    const [iss] = [...this.#storage.getCredentialEvents(credential.d)] as Message<IssueEventBody>[];

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
      this.#log.warn("grant: registry not found", { ri: args.credential.ri });
      throw new Error(`Registry not found for said ${args.credential.ri}`);
    }

    const issuee = args.credential.a.i;
    const recipient = args.recipient || (typeof issuee === "string" && issuee ? issuee : undefined);

    if (!recipient) {
      this.#log.warn("grant: no recipient", { credential: args.credential.d });
      throw new Error("No recipient specified and the credential has no issuee");
    }
    this.#log.debug("grant: building", { credential: args.credential.d, recipient });

    const iss = this.getIssueEvent(args.credential.d);
    const anchorSeal = iss.attachments.SealSourceCouples[0] || iss.attachments.SealSourceTriples[0];

    if (!anchorSeal) {
      throw new Error(`No seal found for issuance ${iss.body.d}`);
    }

    const anchor = this.getAnchorFromSeal(args.credential.i, anchorSeal.digest);

    const grant = RoutedEvent.exchange({
      sender: state.identifier,
      route: RoutedEvent.IPEX_GRANT_ROUTE,
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

    const queryMessage = RoutedEvent.query({
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

    this.#log.debug("query: sending", { aid: id, topic, offset });
    const result = await client.sendMessage(queryMessage, AbortSignal.timeout(10000));

    for (const incoming of result) {
      this.#storage.saveMessage(incoming);
    }

    this.#storage.saveMailboxOffset(id, topic, offset + result.length);
    this.#log.debug("query: received", { aid: id, topic, count: result.length });

    return result;
  }

  async receiveGrants(holderId: string): Promise<CredentialBody[]> {
    const messages = await this.query(holderId, "credential");
    const credentials: CredentialBody[] = [];

    for (const message of messages) {
      const body = message.body as ExchangeEventBody;
      if (body.t !== "exn" || body.r !== RoutedEvent.IPEX_GRANT_ROUTE) {
        continue;
      }

      const { acdc, iss } = RoutedEvent.embeds(message as Message<ExchangeEventBody>);

      if (!acdc || !iss) {
        this.#log.warn("receiveGrants: invalid grant", { holder: holderId });
        throw new Error("Invalid grant message: missing acdc or iss embed");
      }

      this.#storage.saveMessage(acdc);
      this.#storage.saveMessage(iss);
      credentials.push(acdc.body as CredentialBody);
    }

    this.#log.debug("receiveGrants: complete", { holder: holderId, credentials: credentials.length });
    return credentials;
  }

  async export(id: string): Promise<Message[]> {
    const log = await this.loadEventLog(id);
    return log.events;
  }
}
