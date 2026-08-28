/**
 * What other submodules may reach for, beyond the public `KeyEvent` namespace.
 *
 * Split from `main.ts` so the namespace stays the list of things a consumer
 * should see, and an import of this file says at its own call site that it is
 * reaching past it.
 */

export { isKelEventType } from "./key-event.ts";
export { type AnchorTarget, findSealAnchor, type SealAnchorFailure } from "./log.ts";
export * from "./main.ts";
