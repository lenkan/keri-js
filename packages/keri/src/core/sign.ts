import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, type Message, type TransIdxSigGroup, type TransLastIdxSigGroup } from "cesr";
import { type InceptEventBody, isEstablishment, isKeyEvent, isTransferable, type KeyState } from "./key-event.ts";
import { unique } from "./unique.ts";

/**
 * Produces signatures for one key.
 *
 * Synchronous, because the keys this holds are in memory. A key that must be
 * awaited — an HSM, a hardware wallet, a non-extractable WebCrypto `CryptoKey`
 * — is not a `Signer`: sign with it yourself and pass the result as
 * {@link Signature `signatures`}.
 */
export interface Signer {
  /** CESR-encoded public key. */
  readonly publicKey: string;

  /** CESR-encoded signature over `payload`, unindexed. */
  sign(payload: Uint8Array): string;
}

/** An unindexed signature paired with the key that produced it. */
export interface Signature {
  publicKey: string;
  signature: string;
}

export interface Ed25519SignerOptions {
  /** Emit the public key under `Ed25519N`, committing the AID to never rotate. */
  nonTransferable?: boolean;
}

export function ed25519Signer(privateKey: Uint8Array, options?: Ed25519SignerOptions): Signer {
  const code = options?.nonTransferable ? Matter.Code.Ed25519N : Matter.Code.Ed25519;

  return {
    publicKey: encodeText(new Matter({ code, raw: ed25519.getPublicKey(privateKey) })),
    sign(payload: Uint8Array): string {
      return encodeText(Matter.crypto.ed25519_sig(ed25519.sign(payload, privateKey)));
    },
  };
}

interface SignerInput {
  signers?: Signer[];
  /** Signatures produced elsewhere — the way a key holder that must await takes part. */
  signatures?: Signature[];
}

export interface SignEventOptions extends SignerInput {
  /**
   * Required for `ixn`, whose signing keys live in the last establishment event
   * rather than in its own body.
   */
  state?: KeyState;
}

export interface EndorseOptions extends SignerInput {
  /** The identity being spoken for. Its signing keys decide the index. */
  state: KeyState;

  /** Name the signer's latest establishment event instead of pinning sn + digest. */
  latest?: boolean;
}

/**
 * Sign a key event as its own controller, attaching `ControllerIdxSigs`.
 *
 * For an endorsement of anything else — a reply, an exchange, a query — use
 * {@link endorse}. The two are different acts: this signature is what makes the
 * event exist, rather than a statement about a message that already does.
 *
 * Appends to any signatures already attached and returns the same message.
 */
export function signEvent<T extends Message>(event: T, options: SignEventOptions): T {
  if (!isKeyEvent(event)) {
    throw new Error(`Not a key event: t=${JSON.stringify(event.body.t)} — use endorse() instead`);
  }

  const { state } = options;
  if (state && event.body.i !== state.identifier) {
    throw new Error(`Event belongs to ${event.body.i}, not ${state.identifier}`);
  }

  // An establishment event carries the keys it is signed with; everything else
  // is signed with whatever the last establishment left current.
  let keys: string[];
  if (isEstablishment(event.body.t)) {
    keys = (event.body as InceptEventBody).k;
  } else if (state) {
    keys = state.signingKeys;
  } else {
    throw new Error(`Signing a ${event.body.t} needs the signer's key state`);
  }

  event.attachments.ControllerIdxSigs.push(...index(collectSignatures(event, options), keys));
  dedupe(event.attachments.ControllerIdxSigs);

  return event;
}

/**
 * Endorse a routed message — a reply, an exchange, a query — as `state`.
 *
 * The attachment group follows from the identity, not from a choice: a
 * transferable AID is committed to the establishment event its keys came from
 * and gets a `TransIdxSigGroup`, while a non-transferable one has no key
 * history to name and gets a bare couple. Key events belong to
 * {@link signEvent}.
 *
 * Appends to any signatures already attached and returns the same message.
 */
export function endorse<T extends Message>(message: T, options: EndorseOptions): T {
  if (isKeyEvent(message)) {
    throw new Error(`${message.body.t} is a key event — use signEvent() instead`);
  }

  const { state, latest } = options;
  const signatures = collectSignatures(message, options);

  if (state.signingKeys.length === 1 && !isTransferable(state.signingKeys[0])) {
    if (latest) {
      throw new Error("latest is meaningless for a non-transferable identifier: it can never rotate");
    }

    if (signatures.length !== 1 || signatures[0].publicKey !== state.identifier) {
      throw new Error(`A non-transferable identifier signs only with ${state.identifier}`);
    }

    message.attachments.NonTransReceiptCouples.push({ prefix: state.identifier, sig: signatures[0].signature });
    dedupe(message.attachments.NonTransReceiptCouples);

    return message;
  }

  const sigs = index(signatures, state.signingKeys);

  const target = latest
    ? group<TransLastIdxSigGroup>(
        message.attachments.TransLastIdxSigGroups,
        (g) => g.prefix === state.identifier,
        () => ({ prefix: state.identifier, ControllerIdxSigs: [] }),
      )
    : group<TransIdxSigGroup>(
        message.attachments.TransIdxSigGroups,
        (g) =>
          g.prefix === state.identifier &&
          g.snu === state.lastEstablishment.s &&
          g.digest === state.lastEstablishment.d,
        () => ({
          prefix: state.identifier,
          snu: state.lastEstablishment.s,
          digest: state.lastEstablishment.d,
          ControllerIdxSigs: [],
        }),
      );

  target.ControllerIdxSigs.push(...sigs);
  dedupe(target.ControllerIdxSigs);

  return message;
}

function collectSignatures(message: Message, options: SignerInput): Signature[] {
  const { signers = [], signatures = [] } = options;

  if (signers.length === 0 && signatures.length === 0) {
    throw new Error("Nothing to sign with: pass signers, signatures, or both");
  }

  return [
    ...signers.map((signer) => ({ publicKey: signer.publicKey, signature: signer.sign(message.raw) })),
    ...signatures,
  ];
}

/**
 * Index each signature by where its key sits in `keys` — the position
 * `verifyThreshold` resolves it back from. Argument order carries no meaning,
 * so a subset of the keys, in any order, indexes correctly.
 */
function index(signatures: Signature[], keys: string[]): string[] {
  return signatures.map(({ publicKey, signature }) => {
    const idx = keys.indexOf(publicKey);
    if (idx === -1) {
      throw new Error(`Key ${publicKey} is not one of the signing keys: ${keys.join(", ")}`);
    }

    return encodeText(Indexer.convert(Matter.parse(signature), idx));
  });
}

/**
 * Fold into the group already naming this establishment event rather than
 * adding a second one — `verifyExchange` reads only the first group matching a
 * prefix, so a split set would silently lose signatures.
 */
function group<T>(groups: T[], match: (group: T) => boolean, create: () => T): T {
  const existing = groups.find(match);
  if (existing) {
    return existing;
  }

  const created = create();
  groups.push(created);
  return created;
}

function dedupe<T>(entries: T[]): void {
  entries.splice(0, entries.length, ...unique(entries));
}
