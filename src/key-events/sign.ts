import type { Message } from "../cesr/main.ts";
import { collectSignatures, dedupe, indexSignatures, type SignerInput } from "../keys/main.ts";
import { type InceptEventBody, isEstablishment, isKeyEvent, type KeyState } from "./key-event.ts";

export interface SignEventOptions extends SignerInput {
  /**
   * Required for `ixn`, whose signing keys live in the last establishment event
   * rather than in its own body.
   */
  state?: KeyState;
}

/**
 * Sign a key event as its own controller, attaching `ControllerIdxSigs`.
 *
 * For an endorsement of anything else — a reply, an exchange, a query — use
 * `endorse`. The two are different acts: this signature is what makes the event
 * exist, rather than a statement about a message that already does.
 *
 * Appends to any signatures already attached and returns the same message.
 */
export function signEvent<T extends Message>(event: T, options: SignEventOptions): T {
  if (!isKeyEvent(event)) {
    throw new Error(`Not a key event: t=${JSON.stringify(event.body.t)} — use endorse() instead`);
  }

  const { state } = options;
  if (state && event.body.i !== state.identifier) {
    throw new Error(`Event belongs to ${event.body.i}, not ${state.identifier}`);
  }

  // An establishment event carries the keys it is signed with; everything else
  // is signed with whatever the last establishment left current.
  let keys: string[];
  if (isEstablishment(event.body.t)) {
    keys = (event.body as InceptEventBody).k;
  } else if (state) {
    keys = state.signingKeys;
  } else {
    throw new Error(`Signing a ${event.body.t} needs the signer's key state`);
  }

  event.attachments.ControllerIdxSigs.push(...indexSignatures(collectSignatures(event, options), keys));
  dedupe(event.attachments.ControllerIdxSigs);

  return event;
}
