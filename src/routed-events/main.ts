/**
 * Routed messages — those addressed by an `r` route rather than anchored in a log
 * — and the endorsement that speaks for an identifier over one.
 *
 * Re-exported from the package root as the `RoutedEvent` namespace.
 */
export { type EndorseOptions, endorse } from "./endorse.ts";
export type {
  ExchangeEventArgs,
  ExchangeEventBody,
  QueryEventArgs,
  QueryEventBody,
  ReplyEventArgs,
  ReplyEventBody,
  RoutedEventBody,
} from "./routed-event.ts";
export {
  CHALLENGE_RESPONSE_ROUTE,
  embeds,
  exchange,
  IPEX_GRANT_ROUTE,
  isRoutedEvent,
  query,
  reply,
} from "./routed-event.ts";
export type { ExchangeVerification, ExchangeVerificationFailure } from "./verification.ts";
export { verifyExchange, verifyReply } from "./verification.ts";
