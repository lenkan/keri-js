const PREFIX = new TextEncoder().encode("KJS1");
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 310000;

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
      salt: Uint8Array.from(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    encryptionKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  return key;
}

interface Ciphertext {
  salt: Uint8Array;
  iv: Uint8Array;
  encrypted: Uint8Array;
}

function hasV1Prefix(ciphertext: Uint8Array): boolean {
  if (ciphertext.length < PREFIX.length) {
    return false;
  }

  for (let i = 0; i < PREFIX.length; i++) {
    if (ciphertext[i] !== PREFIX[i]) {
      return false;
    }
  }

  return true;
}

function parseCiphertext(ciphertext: Uint8Array): Ciphertext {
  if (!hasV1Prefix(ciphertext)) {
    throw new Error("Invalid encrypted payload");
  }

  const headerLength = PREFIX.length + SALT_LENGTH + IV_LENGTH;
  if (ciphertext.length < headerLength + AUTH_TAG_LENGTH) {
    throw new Error("Invalid encrypted payload");
  }

  const saltStart = PREFIX.length;
  const ivStart = saltStart + SALT_LENGTH;
  const encryptedStart = ivStart + IV_LENGTH;

  return {
    salt: ciphertext.slice(saltStart, ivStart),
    iv: ciphertext.slice(ivStart, encryptedStart),
    encrypted: ciphertext.slice(encryptedStart),
  };
}

async function encrypt(data: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(passphrase, salt);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, Uint8Array.from(data));

  const result = new Uint8Array(PREFIX.length + salt.byteLength + iv.byteLength + encrypted.byteLength);
  result.set(PREFIX, 0);
  result.set(salt, PREFIX.length);
  result.set(iv, PREFIX.length + salt.byteLength);
  result.set(new Uint8Array(encrypted), PREFIX.length + salt.byteLength + iv.byteLength);

  return result;
}

async function decrypt(ciphertext: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const { salt, iv, encrypted } = parseCiphertext(ciphertext);
  const key = await deriveKey(passphrase, salt);

  try {
    const result = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(encrypted),
    );
    return new Uint8Array(result);
  } catch (err) {
    throw new Error("Could not decrypt data", {
      cause: err,
    });
  }
}

/**
 * PBKDF2 (SHA-256, 310k iterations) + AES-256-GCM with a random salt and IV.
 *
 * The KDF parameters are not encoded in the ciphertext, so behaviour under the
 * "KJS1" prefix can never change: any change to the scheme needs a new prefix
 * or already-encrypted keystores stop opening.
 */
export class PassphraseEncrypter implements Encrypter {
  #passphrase: string;

  constructor(passphrase: string) {
    this.#passphrase = passphrase;
  }

  async encrypt(data: Uint8Array): Promise<Uint8Array> {
    return await encrypt(data, this.#passphrase);
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    return await decrypt(ciphertext, this.#passphrase);
  }
}
