import { cesr, Indexer, Matter, Message, parse } from "cesr";
import type { KeyEventBody } from "./key-event.ts";
import { MailboxClient } from "./mailbox-client.ts";
import { verifyOrThrow } from "./verify.ts";
import type { ReceiptEvent } from "./receipt-event.ts";

export interface WitnessEndpoint {
  aid: string;
  url: string;
}

async function receipt(event: Message<KeyEventBody>, witnessUrl: string): Promise<ReceiptEvent> {
  const url = new URL("/receipts", witnessUrl);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Invalid protocol: ${url}`);
  }

  const fetchResponse = await fetch(url, {
    method: "POST",
    body: JSON.stringify(event.body),
    headers: {
      "Content-Type": "application/cesr+json",
      "CESR-ATTACHMENT": event.attachments.text(),
    },
  });

  if (!fetchResponse.ok || !fetchResponse.body) {
    throw new Error(`Failed to submit event to witness: ${fetchResponse.status} ${fetchResponse.statusText}`);
  }

  for await (const incoming of parse(fetchResponse.body)) {
    if (incoming.body.t === "rct" && incoming.body.d === event.body.d) {
      for (const couple of incoming.attachments.NonTransReceiptCouples) {
        const sig = Indexer.convert(Matter.parse(couple.sig), 0).text();
        verifyOrThrow(event.raw, {
          keys: [couple.prefix],
          sigs: [sig],
          threshold: "1",
        });
      }

      return incoming as ReceiptEvent;
    }
  }

  throw new Error(`No receipt returned from ${witnessUrl}`);
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
export async function submitToWitnesses(event: Message<KeyEventBody>, endpoints: WitnessEndpoint[]): Promise<string[]> {
  // TODO: implement the spec's round-robin approach where receipts collected from
  // earlier witnesses are forwarded to later ones in the same pass, reducing total
  // network exchanges from N+(N×(N-1)) to at most 2×N.
  const receipts: Record<string, Message> = {};
  const wigs = new Set<string>();
  const wits = endpoints.map((e) => e.aid);

  for (const endpoint of endpoints) {
    const response = await receipt(event, endpoint.url);

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
    const client = new MailboxClient({ id: endpoint.aid, url: endpoint.url });

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
