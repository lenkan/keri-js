import type { Message, TransIdxSigGroup, TransLastIdxSigGroup } from "../cesr/main.ts";
import { isKeyEvent, type KeyState } from "../key-events/main.ts";
import { collectSignatures, dedupe, indexSignatures, isTransferable, type SignerInput } from "../keys/main.ts";

export interface EndorseOptions extends SignerInput {
  /** The identity being spoken for. Its signing keys decide the index. */
  state: KeyState;

  /** Name the signer's latest establishment event instead of pinning sn + digest. */
  latest?: boolean;
}

/**
 * Endorse a routed message — a reply, an exchange, a query — as `state`.
 *
 * The attachment group follows from the identity, not from a choice: a
 * transferable AID is committed to the establishment event its keys came from
 * and gets a `TransIdxSigGroup`, while a non-transferable one has no key
 * history to name and gets a bare couple. Key events belong to `signEvent`.
 *
 * Appends to any signatures already attached and returns the same message.
 */
export function endorse<T extends Message>(message: T, options: EndorseOptions): T {
  if (isKeyEvent(message)) {
    throw new Error(`${message.body.t} is a key event — use signEvent() instead`);
  }

  // A receipt is signed over the event it receipts, which this never sees.
  if (message.body.t === "rct") {
    throw new Error("A receipt is signed over the event it receipts — use receipt() instead");
  }

  const { state, latest } = options;
  const signatures = collectSignatures(message, options);

  if (!isTransferable(state.identifier)) {
    if (latest) {
      throw new Error("latest is meaningless for a non-transferable identifier: it can never rotate");
    }

    if (signatures.length !== 1 || signatures[0].publicKey !== state.identifier) {
      throw new Error(`A non-transferable identifier signs only with ${state.identifier}`);
    }

    message.attachments.NonTransReceiptCouples.push({ prefix: state.identifier, sig: signatures[0].signature });
    dedupe(message.attachments.NonTransReceiptCouples);

    return message;
  }

  const sigs = indexSignatures(signatures, state.signingKeys);
  const { TransIdxSigGroups, TransLastIdxSigGroups } = message.attachments;

  let target: TransIdxSigGroup | TransLastIdxSigGroup;
  if (latest) {
    discard(TransIdxSigGroups, state.identifier);
    target = group(TransLastIdxSigGroups, state.identifier, () => ({
      prefix: state.identifier,
      ControllerIdxSigs: [],
    }));
  } else {
    discard(TransLastIdxSigGroups, state.identifier);
    const pinned = group(TransIdxSigGroups, state.identifier, () => ({
      prefix: state.identifier,
      snu: state.lastEstablishment.s,
      digest: state.lastEstablishment.d,
      ControllerIdxSigs: [],
    }));

    // A group left by an earlier establishment holds signatures indexed against
    // keys that are no longer current, so re-endorsing after a rotation
    // replaces the seal and drops them rather than keeping both.
    if (pinned.snu !== state.lastEstablishment.s || pinned.digest !== state.lastEstablishment.d) {
      pinned.snu = state.lastEstablishment.s;
      pinned.digest = state.lastEstablishment.d;
      pinned.ControllerIdxSigs.length = 0;
    }

    target = pinned;
  }

  target.ControllerIdxSigs.push(...sigs);
  dedupe(target.ControllerIdxSigs);

  return message;
}

/**
 * Fold into the group already carrying this prefix rather than adding a second
 * one — `verifyReply` and `verifyExchange` read only the first group matching a
 * prefix, so a split set would silently lose signatures.
 */
function group<T extends { prefix: string }>(groups: T[], prefix: string, create: () => T): T {
  const existing = groups.find((g) => g.prefix === prefix);
  if (existing) {
    return existing;
  }

  const created = create();
  groups.push(created);
  return created;
}

/**
 * Drop this prefix from the group kind we are not writing to. The verifier
 * prefers `TransIdxSigGroups`, so leaving both kinds behind would hide one.
 */
function discard(groups: { prefix: string }[], prefix: string): void {
  for (let i = groups.length - 1; i >= 0; i--) {
    if (groups[i].prefix === prefix) {
      groups.splice(i, 1);
    }
  }
}
