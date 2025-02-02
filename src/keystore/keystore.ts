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

export interface KeyStore {
  incept(): Promise<Key>;
  rotate(currentKey: string): Promise<Key>;

  sign(publicKey: string, message: Uint8Array): Promise<string>;
}
