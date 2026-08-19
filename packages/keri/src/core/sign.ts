import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, type Message } from "cesr";

/**
 * Produces signatures for one key.
 *
 * Async because the keys worth protecting do not surrender their bytes: an HSM,
 * a hardware wallet and a non-extractable WebCrypto `CryptoKey` all sign
 * asynchronously. Implement this over whatever holds the key.
 */
export interface Signer {
  /** CESR-encoded public key. */
  readonly publicKey: string;

  /** CESR-encoded signature over `payload`, unindexed. */
  sign(payload: Uint8Array): Promise<string>;
}

export interface Ed25519SignerOptions {
  /** Emit the public key under `Ed25519N`, committing the AID to never rotate. */
  nonTransferable?: boolean;
}

export function ed25519Signer(privateKey: Uint8Array, options?: Ed25519SignerOptions): Signer {
  const code = options?.nonTransferable ? Matter.Code.Ed25519N : Matter.Code.Ed25519;

  return {
    publicKey: encodeText(new Matter({ code, raw: ed25519.getPublicKey(privateKey) })),
    async sign(payload: Uint8Array): Promise<string> {
      return encodeText(Matter.crypto.ed25519_sig(ed25519.sign(payload, privateKey)));
    },
  };
}

/**
 * Attach controller signatures over `event.raw`, one per signer, indexed by
 * position in `signers` — so the order must match the event's signing keys.
 *
 * Appends to any signatures already attached and returns the same message.
 */
export async function signEvent<T extends Message>(event: T, signers: Signer[]): Promise<T> {
  const signatures = await Promise.all(signers.map((signer) => signer.sign(event.raw)));

  event.attachments.ControllerIdxSigs.push(
    ...signatures.map((signature, index) => encodeText(Indexer.convert(Matter.parse(signature), index))),
  );

  return event;
}
