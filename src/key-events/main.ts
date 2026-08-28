/**
 * Key events — the messages that make up a Key Event Log, the receipt that
 * endorses one, and the log itself.
 *
 * Re-exported from the package root as the `KeyEvent` namespace. Submodules
 * needing more than this list import `./internal.ts`.
 */
export type {
  DelegatedInceptArgs,
  DelegatedRotateArgs,
  DipEventBody,
  DrtEventBody,
  InceptArgs,
  InceptEventBody,
  InteractArgs,
  InteractEventBody,
  KeyEventBody,
  KeyState,
  RotateArgs,
  RotateEventBody,
} from "./key-event.ts";
export {
  attachSourceSeal,
  backersFor,
  delegatedIncept,
  delegatedRotate,
  incept,
  interact,
  isEstablishment,
  isKeyEvent,
  keyEventSeal,
  rotate,
} from "./key-event.ts";
export { type AppendOptions, KeyEventLog } from "./log.ts";
export { applyReceipt, type ReceiptArgs, type ReceiptEventBody, receipt } from "./receipt-event.ts";
export { type SignEventOptions, signEvent } from "./sign.ts";
