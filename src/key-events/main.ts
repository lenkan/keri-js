/**
 * Key events — the messages that make up a Key Event Log, plus the receipt that
 * endorses one.
 *
 * Re-exported from the package root as the `KeyEvent` namespace, so
 * `KeyEvent.incept(...)` and `import { incept } from "keri/key-events"` name the
 * same function.
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
  ReceiptEventBody,
  RotateArgs,
  RotateEventBody,
} from "../core/main.ts";
export {
  attachSourceSeal,
  delegatedIncept,
  delegatedRotate,
  incept,
  interact,
  isEstablishment,
  isKeyEvent,
  keyEventSeal,
  receipt,
  rotate,
} from "../core/main.ts";
