/**
 * Turning a KERI message body into bytes: version string, canonical
 * serialisation, and the SAID that commits to the result.
 *
 * Shared by every protocol submodule — a `vcp` and an `icp` are sized and
 * saidified the same way.
 */
export {
  DUMMY_SAID,
  DUMMY_VERSION,
  type EncodeEventArgs,
  encodeEvent,
  formatDate,
  randomNonce,
  type VerifyEventSaidArgs,
  verifyEventSaid,
} from "./encode.ts";
export { type SaidArgs, saidify } from "./said.ts";
