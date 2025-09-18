import { ed25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import {
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

export interface FileSystemKeyStoreOptions {
  encrypter: Encrypter;
  storage: KeyValueStorage;
}

export class KeyStore {
  storage: KeyValueStorage;
  encrypter: Encrypter;

  constructor(options: FileSystemKeyStoreOptions) {
    this.encrypter = options.encrypter;
    this.storage = options.storage;
  }

  private async load(publicKey: string): Promise<[Uint8Array, Uint8Array]> {
    const value = await this.storage.get(publicKey);

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

    const next = encodeMatter({
      code: MatterCode.Blake3_256,
      raw: blake3.create({ dkLen: 32 }).update(current).digest(),
    });

    await this.storage.set(
      current,
      [
        encodeBase64Url(await this.encrypter.encrypt(key0)),
        encodeBase64Url(await this.encrypter.encrypt(key1)),
        "\n",
      ].join("\n"),
    );

    return { current, next };
  }

  async incept(): Promise<Key> {
    const key0 = ed25519.utils.randomPrivateKey();
    const key1 = ed25519.utils.randomPrivateKey();

    return await this.import(key0, key1);
  }

  async rotate(currentKey: string): Promise<Key> {
    const [, key0] = await this.load(currentKey);
    const key1 = ed25519.utils.randomPrivateKey();

    const current = encodeMatter({
      code: MatterCode.Ed25519,
      raw: ed25519.getPublicKey(key0),
    });

    const next = encodeMatter({
      code: MatterCode.Blake3_256,
      raw: blake3.create({ dkLen: 32 }).update(current).digest(),
    });

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
