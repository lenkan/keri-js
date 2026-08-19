/**
 * Routed messages — those addressed by an `r` route rather than anchored in a log.
 *
 * Re-exported from the package root as the `RoutedEvent` namespace.
 */
export type {
  ExchangeEventArgs,
  ExchangeEventBody,
  QueryEventArgs,
  QueryEventBody,
  ReplyEventArgs,
  ReplyEventBody,
  RoutedEventBody,
} from "../core/main.ts";
export { embeds, exchange, IPEX_GRANT_ROUTE, isRoutedEvent, query, reply } from "../core/main.ts";
