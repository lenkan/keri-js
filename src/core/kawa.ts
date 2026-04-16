import { cesr, Matter, Message } from "../cesr/__main__.ts";
import type { KeyEventBody } from "./key-event.ts";
import { MailboxClient } from "./mailbox-client.ts";
import { WitnessClient } from "./witness-client.ts";

export interface WitnessEndpoint {
  aid: string;
  url: string;
}

/**
 * KERI Algorithm for Witness Agreement (KAWA).
 *
 * Collects receipts from all witnesses, then distributes those receipts back
 * to all witnesses. The event must already have controller signatures attached.
 *
 * @param event Pre-signed key event (ControllerIdxSigs already on attachments)
 * @param endpoints Pre-resolved endpoints for each witness
 * @returns Indexed witness signatures (wigs)
 */
export async function submitToWitnesses(
  event: Message<KeyEventBody>,
  endpoints: WitnessEndpoint[],
  fetch?: typeof globalThis.fetch,
): Promise<string[]> {
  // TODO: implement the spec's round-robin approach where receipts collected from
  // earlier witnesses are forwarded to later ones in the same pass, reducing total
  // network exchanges from N+(N×(N-1)) to at most 2×N.
  const receipts: Record<string, Message> = {};
  const wigs = new Set<string>();
  const wits = endpoints.map((e) => e.aid);

  for (const endpoint of endpoints) {
    const client = new WitnessClient(endpoint.url, fetch);
    const response = await client.receipt(event);

    if (response.attachments.NonTransReceiptCouples.length > 0) {
      const receiptCouple = response.attachments.NonTransReceiptCouples[0];
      const witnessIndex = wits.indexOf(receiptCouple.prefix);

      if (witnessIndex !== -1) {
        const signature = Matter.parse(receiptCouple.sig);
        wigs.add(cesr.index(signature, witnessIndex).text());
      }
    }

    receipts[endpoint.aid] = response;
  }

  for (const endpoint of endpoints) {
    const client = new MailboxClient({ id: endpoint.aid, url: endpoint.url, fetch });

    for (const [other, receipt] of Object.entries(receipts)) {
      if (other === endpoint.aid) {
        continue;
      }

      const message = new Message(receipt.body, {
        NonTransReceiptCouples: receipt.attachments.NonTransReceiptCouples,
      });

      await client.sendMessage(message);
    }
  }

  return Array.from(wigs);
}
