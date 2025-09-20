import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import {
  cesr,
  decodeBase64Url,
  encodeBase64Url,
  encodeIndexer,
  encodeMatter,
  IndexCode,
  MatterCode,
} from "cesr/__unstable__";
import type { Encrypter } from "./encrypt.ts";
import { type KeyValueStorage } from "../events/event-store.ts";

export interface Key {
  /**
   * The public key of the tranferable key.
   */
  current: string;

  /**
   * Digest of the next public key of the key pair.
   */
  next: string;
}

export interface KeyManagerOptions {
  encrypter: Encrypter;
  storage: KeyValueStorage;
}

function createDigest(key: Uint8Array): string {
  const encoded = encodeMatter({
    code: MatterCode.Ed25519,
    raw: ed25519.getPublicKey(key),
  });

  const next = encodeMatter({
    code: MatterCode.Blake3_256,
    raw: blake3.create({ dkLen: 32 }).update(new TextEncoder().encode(encoded)).digest(),
  });

  return next;
}

export class KeyManager {
  storage: KeyValueStorage;
  encrypter: Encrypter;

  constructor(options: KeyManagerOptions) {
    this.encrypter = options.encrypter;
    this.storage = options.storage;
  }

  private async load(publicKey: string): Promise<[Uint8Array, Uint8Array]> {
    const value = await this.storage.get(`keys.${publicKey}`);

    if (!value) {
      throw new Error(`Key ${publicKey} not found`);
    }

    const [key0, key1] = value.split("\n");

    return [await this.encrypter.decrypt(decodeBase64Url(key0)), await this.encrypter.decrypt(decodeBase64Url(key1))];
  }

  async import(key0: Uint8Array, key1: Uint8Array): Promise<Key> {
    const current = encodeMatter({
      code: MatterCode.Ed25519,
      raw: ed25519.getPublicKey(key0),
    });

    const next = createDigest(key1);

    await this.storage.set(
      `keys.${current}`,
      [
        encodeBase64Url(await this.encrypter.encrypt(key0)),
        encodeBase64Url(await this.encrypter.encrypt(key1)),
        "\n",
      ].join("\n"),
    );

    return { current, next };
  }

  async incept(): Promise<Key> {
    const key0 = ed25519.utils.randomSecretKey();
    const key1 = ed25519.utils.randomSecretKey();

    return await this.import(key0, key1);
  }

  async rotate(publicKey: string): Promise<Key> {
    const [, key0] = await this.load(publicKey);
    const key1 = ed25519.utils.randomSecretKey();

    const current = encodeMatter({
      code: MatterCode.Ed25519,
      raw: ed25519.getPublicKey(key0),
    });

    const next = createDigest(key1);

    await this.import(key0, key1);

    return { current, next };
  }

  async sign(publicKey: string, message: Uint8Array, index?: number): Promise<string> {
    const [key] = await this.load(publicKey);
    const signature = ed25519.sign(message, key);

    if (index !== undefined) {
      return encodeIndexer({
        code: IndexCode.Ed25519_Sig,
        raw: signature,
        index,
      });
    }

    return encodeMatter({
      code: MatterCode.Ed25519_Sig,
      raw: signature,
    });
  }
}

export function verify(publicKey: string, message: Uint8Array, signature: string): boolean {
  const key = cesr.decodeMatter(publicKey);
  const sig = cesr.decodeMatter(signature);

  switch (key.code) {
    case MatterCode.Ed25519:
    case MatterCode.Ed25519N:
      switch (sig.code) {
        case MatterCode.Ed25519_Sig:
          return ed25519.verify(sig.raw, message, key.raw);
        default:
          throw new Error(`Unsupported signature code: ${sig.code}`);
      }
    default:
      throw new Error(`Unsupported key code: ${key.code}`);
  }
}
