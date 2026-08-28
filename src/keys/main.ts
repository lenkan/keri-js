/**
 * Keys, the signatures made with them, and how many of them are enough.
 *
 * Everything here is below any particular message type: a `Signer` does not know
 * what it is signing, and `verifyThreshold` does not know which log the keys came
 * from. Attaching a signature to a message is each protocol's own job.
 */
export { nextKeyDigest } from "./digest.ts";
export { type GenerateKeyPairOptions, generateKeyPair, isTransferable, type KeyPair } from "./keys.ts";
export {
  collectSignatures,
  dedupe,
  type Ed25519SignerOptions,
  ed25519Signer,
  indexSignatures,
  type Signature,
  type Signer,
  type SignerInput,
} from "./signer.ts";
export { parseThreshold, type Threshold, type WeightedThreshold } from "./threshold.ts";
export {
  type VerifyOptions,
  type VerifyResult,
  verifySignature,
  verifySignatures,
  verifySignaturesOrThrow,
  verifyThreshold,
  verifyThresholdOrThrow,
} from "./verify.ts";
