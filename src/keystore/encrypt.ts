export interface Encrypter {
  encrypt(data: Uint8Array): Promise<Uint8Array>;
  decrypt(data: Uint8Array): Promise<Uint8Array>;
}

async function deriveKey(passphrase: string, salt: Uint8Array) {
  const encoder = new TextEncoder();
  const encryptionKey = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, [
    "deriveBits",
    "deriveKey",
  ]);

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    encryptionKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  return key;
}

export class PassphraseEncrypter implements Encrypter {
  #passphrase: string;

  constructor(passphrase: string) {
    this.#passphrase = passphrase;
  }

  async encrypt(data: Uint8Array) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(this.#passphrase, salt);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

    const result = new Uint8Array(salt.byteLength + iv.byteLength + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.byteLength);
    result.set(new Uint8Array(encrypted), salt.byteLength + iv.byteLength);

    return result;
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    const salt = ciphertext.slice(0, 16);
    const key = await deriveKey(this.#passphrase, salt);
    const iv = ciphertext.slice(16, 32);
    const encrypted = ciphertext.slice(32);

    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted));
  }
}
