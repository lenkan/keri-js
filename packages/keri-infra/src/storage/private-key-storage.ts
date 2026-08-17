export interface PrivateKeyStorage {
  saveKey(publicKey: string, digest: string, encryptedPrivKey: string): void;
  getEncryptedPrivateKey(publicKey: string): string;
  getPublicKeyByDigest(digest: string): string;
}
