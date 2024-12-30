import libsodium, { type KeyPair } from "libsodium-wrappers-sumo";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";
import { blake3 } from "@noble/hashes/blake3";

export interface SaltyKeyArgs {
  password?: string;
  /**
   * CESR Encoded 128 bit salt
   */
  salt: string;
}

export class SaltyKey {
  private readonly _keypair: KeyPair;

  public readonly publicKeyDigest: string;
  public readonly publicKey: string;

  constructor(args: SaltyKeyArgs) {
    const opslimit = 2;
    const memlimit = 67108864;
    const salt = cesr.decode(args.salt);
    const seed0 = libsodium.crypto_pwhash(
      32,
      args.password ?? "",
      salt.buffer,
      opslimit,
      memlimit,
      libsodium.crypto_pwhash_ALG_ARGON2ID13,
    );

    this._keypair = libsodium.crypto_sign_seed_keypair(seed0, "uint8array");

    this.publicKey = cesr.encode(MatterCode.Ed25519, this._keypair.publicKey);
    this.publicKeyDigest = cesr.encode(
      MatterCode.Blake3_256,
      blake3.create({ dkLen: 32 }).update(this.publicKey).digest(),
    );
  }

  sign(data: Uint8Array): string {
    return cesr.encode(MatterCode.Ed25519_Sig, libsodium.crypto_sign_detached(data, this._keypair.privateKey));
  }
}
