import { encodeText, Indexer, Matter, Message } from "../cesr/main.ts";
import { DUMMY_VERSION, encodeEvent } from "../events/main.ts";
import { collectSignatures, dedupe, isTransferable, type Signature, type Signer } from "../keys/main.ts";
import type { KeyEventBody } from "./key-event.ts";

export type ReceiptEventBody = {
  v: string;
  t: "rct";
  d: string;
  i: string;
  s: string;
};

export interface ReceiptArgs {
  signers?: Signer[];
  /** Signatures produced elsewhere. They must be over the receipted event, not over the receipt. */
  signatures?: Signature[];
  /**
   * The set a witness indexes its signature against — see {@link backersFor}. A signer listed in
   * it receipts as a witness, with a signature indexed by its position there; anyone else receipts
   * with a bare couple naming its own key.
   *
   * Passing it is the choice to receipt *as a witness*, so a backer that omits it receipts in the
   * generic form instead. Both are valid: a validator promotes the couple back to an indexed
   * signature once it knows the backer set.
   */
  backers?: string[];
}

/**
 * Build the `rct` receipting `event`, signed by whoever `args` names.
 *
 * Takes the event rather than its `d`/`i`/`s` because those three fields are exactly what a receipt
 * copies from it — and because the signatures are over the event's bytes, not the receipt's. Omit
 * `args` for an unsigned receipt.
 *
 * Note `rct` is not itself a KEL event type — a receipt is *about* a key event.
 */
export function receipt(event: Message<KeyEventBody>, args?: ReceiptArgs): Message<ReceiptEventBody> {
  const body = encodeEvent<ReceiptEventBody>(
    {
      v: DUMMY_VERSION,
      t: "rct",
      d: event.body.d,
      i: event.body.i,
      s: event.body.s,
    },
    { labels: [] },
  );

  const message = new Message<ReceiptEventBody>(body);
  if (args === undefined) {
    return message;
  }

  const backers = args.backers ?? [];

  for (const { publicKey, signature } of collectSignatures(event, args)) {
    if (isTransferable(publicKey)) {
      throw new Error(`${publicKey} is transferable, so it cannot receipt on its own — use endorse() instead`);
    }

    const index = backers.indexOf(publicKey);
    if (index === -1) {
      message.attachments.NonTransReceiptCouples.push({ prefix: publicKey, sig: signature });
    } else {
      message.attachments.WitnessIdxSigs.push(encodeText(Indexer.convert(Matter.parse(signature), index)));
    }
  }

  return message;
}

/**
 * Fold `receipt`'s signatures onto the event it receipts, as `WitnessIdxSigs`.
 *
 * A couple names its signer by prefix and an indexed signature names it by position, so both
 * resolve against the same backer set. A couple from outside that set is dropped: a key event has
 * nowhere to carry a receipt from someone who is not one of its backers.
 *
 * Nothing is verified here — that is {@link KeyEventLog.append}'s job, the same split
 * {@link signEvent} keeps.
 *
 * Appends to any signatures already attached and returns the same event.
 */
export function applyReceipt(
  event: Message<KeyEventBody>,
  receipt: Message<ReceiptEventBody>,
  backers: string[],
): Message<KeyEventBody> {
  if (receipt.body.d !== event.body.d) {
    throw new Error(`Receipt is for ${receipt.body.d}, not ${event.body.d}`);
  }

  const wigs = event.attachments.WitnessIdxSigs;

  for (const sig of receipt.attachments.WitnessIdxSigs) {
    const { index } = Indexer.parse(sig);
    if (index >= backers.length) {
      throw new Error(`Receipt signature is indexed ${index}, past the ${backers.length} backers of ${event.body.d}`);
    }

    wigs.push(sig);
  }

  for (const couple of receipt.attachments.NonTransReceiptCouples) {
    const index = backers.indexOf(couple.prefix);
    if (index !== -1) {
      wigs.push(encodeText(Indexer.convert(Matter.parse(couple.sig), index)));
    }
  }

  dedupe(wigs);

  return event;
}
