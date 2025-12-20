import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { PassphraseEncrypter, type Encrypter } from "./encrypt.ts";
import { type KeyValueStorage } from "../events/event-store.ts";
import { cesr, Matter } from "cesr";
import { decodeBase64Url, encodeBase64Url } from "cesr/__unstable__";

export interface KeyManagerOptions {
  passphrase?: string;
  storage: KeyValueStorage;
}

export class KeyManager {
  storage: KeyValueStorage;
  encrypter: Encrypter;

  constructor(options: KeyManagerOptions) {
    this.encrypter = new PassphraseEncrypter(options.passphrase);
    this.storage = options.storage;
  }

  private async load(publicKey: string): Promise<Uint8Array> {
    const value = await this.storage.get(publicKey);

    if (!value) {
      throw new Error(`Key ${publicKey} not found`);
    }

    return await this.encrypter.decrypt(decodeBase64Url(value));
  }

  async import(key: Uint8Array): Promise<string> {
    const text = cesr.crypto.ed25519(ed25519.getPublicKey(key)).text();
    const data = await this.encrypter.encrypt(key);

    await this.storage.set(text, encodeBase64Url(data));

    return text;
  }

  async incept(): Promise<string> {
    const key = ed25519.utils.randomSecretKey();
    return await this.import(key);
  }

  async sign(publicKey: string, message: Uint8Array, index?: number): Promise<string> {
    const key = await this.load(publicKey);
    const signature = ed25519.sign(message, key);

    if (index !== undefined) {
      return cesr.crypto.ed25519_sig(signature, index).text();
    }

    return cesr.crypto.ed25519_sig(signature).text();
  }

  static createDigest = createDigest;
  static verify = verify;
}

export function createDigest(key: string): string {
  const next = cesr.crypto
    .blake3_256(blake3.create({ dkLen: 32 }).update(new TextEncoder().encode(key)).digest())
    .text();

  return next;
}

export function verify(publicKey: string, message: Uint8Array, signature: string): boolean {
  const key = Matter.parse(publicKey);
  const sig = Matter.parse(signature);

  switch (key.code) {
    case Matter.Code.Ed25519:
    case Matter.Code.Ed25519N:
      switch (sig.code) {
        case Matter.Code.Ed25519_Sig:
          return ed25519.verify(sig.raw, message, key.raw);
        default:
          throw new Error(`Unsupported signature code: ${sig.code}`);
      }
    default:
      throw new Error(`Unsupported key code: ${key.code}`);
  }
}
