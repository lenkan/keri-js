import type { Message, TransIdxSigGroup, TransLastIdxSigGroup } from "cesr";
import { verifyEventSaid } from "./events.ts";
import type { KeyState } from "./key-event.ts";
import type { ExchangeEventBody, ReplyEventBody } from "./routed-event.ts";
import { verifyThreshold } from "./verify.ts";

export type ExchangeVerificationFailure =
  | { kind: "said-mismatch"; error: string }
  | { kind: "no-signature"; error: string }
  | { kind: "stale-establishment"; error: string }
  | { kind: "invalid-signature"; error: string };

export type ExchangeVerification = { ok: true } | ({ ok: false } & ExchangeVerificationFailure);

function verifyGroupSignatures(
  message: Message,
  state: KeyState,
  group: TransIdxSigGroup | TransLastIdxSigGroup,
): ExchangeVerification {
  const result = verifyThreshold(message.raw, {
    keys: state.signingKeys,
    threshold: state.signingThreshold,
    sigs: group.ControllerIdxSigs,
  });

  return result.ok ? { ok: true } : { ok: false, kind: "invalid-signature", error: result.error };
}

function verifyRoutedMessage(message: Message, state: KeyState, subject: string): ExchangeVerification {
  const said = verifyEventSaid(message.body, { subject });
  if (!said.ok) {
    return { ok: false, kind: "said-mismatch", error: said.error };
  }

  const group = message.attachments.TransIdxSigGroups.find((g) => g.prefix === state.identifier);
  if (group) {
    const establishment = state.lastEstablishment;
    const sealed = BigInt(`0x${group.snu}`);
    const current = BigInt(`0x${establishment.s}`);

    if (sealed !== current || group.digest !== establishment.d) {
      return {
        ok: false,
        kind: "stale-establishment",
        error: `Signature seals establishment event ${group.digest} at sn ${sealed}, but the key state's last establishment is ${establishment.d} at sn ${current}`,
      };
    }

    return verifyGroupSignatures(message, state, group);
  }

  const last = message.attachments.TransLastIdxSigGroups.find((g) => g.prefix === state.identifier);
  if (last) {
    return verifyGroupSignatures(message, state, last);
  }

  return { ok: false, kind: "no-signature", error: `No signature group for ${state.identifier}` };
}

/**
 * Verify a signed `exn` against a sender's key state.
 *
 * A `TransIdxSigGroup` seal must name the state's last establishment event —
 * historical key states are rejected rather than resolved, so a signature made
 * before a rotation cannot be replayed after it. The caller decides whether a
 * `stale-establishment` result means "refetch the KEL" or "reject".
 */
export function verifyExchange(message: Message<ExchangeEventBody>, state: KeyState): ExchangeVerification {
  return verifyRoutedMessage(message, state, "exn");
}

/** Same checks for a signed `rpy` — e.g. an `/end/role/add` a controller registers with its mailbox. */
export function verifyReply(message: Message<ReplyEventBody>, state: KeyState): ExchangeVerification {
  return verifyRoutedMessage(message, state, "rpy");
}
