import { ed25519 } from "@noble/curves/ed25519";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";
import { decodeBase64, encodeBase64 } from "../parser/base64.ts";
import { decrypt, encrypt } from "./encrypt.ts";
import { join } from "node:path";
import { blake3 } from "@noble/hashes/blake3";
import type { KeyStore, Key } from "./keystore.ts";

export interface FileSystemKeyStoreOptions {
  dir: string;
  passphrase: string;
}

export class FileSystemKeyStore implements KeyStore {
  options: FileSystemKeyStoreOptions;

  constructor(options: FileSystemKeyStoreOptions) {
    this.options = options;
  }

  private async load(publicKey: string): Promise<[Uint8Array, Uint8Array]> {
    const value = await readFile(join(this.options.dir, publicKey), "utf-8");

    const [key0, key1] = value.split("\n");

    return [
      await decrypt(this.options.passphrase, decodeBase64(key0)),
      await decrypt(this.options.passphrase, decodeBase64(key1)),
    ];
  }

  async import(key0: Uint8Array, key1: Uint8Array) {
    await mkdir(this.options.dir, { recursive: true });

    const current = cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(key0));
    const next = cesr.encode(MatterCode.Blake3_256, blake3.create({ dkLen: 32 }).update(current).digest());

    await writeFile(
      join(this.options.dir, current),
      [
        encodeBase64(await encrypt(this.options.passphrase, key0)),
        encodeBase64(await encrypt(this.options.passphrase, key1)),
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

    const current = cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(key0));
    const next = cesr.encode(MatterCode.Blake3_256, blake3.create({ dkLen: 32 }).update(current).digest());

    await writeFile(
      join(this.options.dir, current),
      [
        encodeBase64(await encrypt(this.options.passphrase, key0)),
        encodeBase64(await encrypt(this.options.passphrase, key1)),
        "\n",
      ].join("\n"),
    );

    return { current, next };
  }

  async sign(publicKey: string, message: Uint8Array): Promise<string> {
    const [key] = await this.load(publicKey);
    return cesr.sign(message, key, "ed25519");
  }
}
