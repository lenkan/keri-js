import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, type Message } from "../cesr/main.ts";

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

export interface SignerInput {
  signers?: Signer[];
  /** Signatures produced elsewhere — the way a key holder that must await takes part. */
  signatures?: Signature[];
}

/**
 * Sign `message.raw` with everything `options` names.
 *
 * The message signed is not always the one the signatures end up on: a receipt
 * is signed over the event it receipts.
 */
export function collectSignatures(message: Message, options: SignerInput): Signature[] {
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
export function indexSignatures(signatures: Signature[], keys: string[]): string[] {
  return signatures.map(({ publicKey, signature }) => {
    const idx = keys.indexOf(publicKey);
    if (idx === -1) {
      throw new Error(`Key ${publicKey} is not one of the signing keys: ${keys.join(", ")}`);
    }

    return encodeText(Indexer.convert(Matter.parse(signature), idx));
  });
}

/** A replayed stream would otherwise double every signature it carries. */
export function dedupe<T>(entries: T[]): void {
  const seen = new Set<string>();

  entries.splice(
    0,
    entries.length,
    ...entries.filter((entry) => {
      const key = JSON.stringify(entry);
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    }),
  );
}
