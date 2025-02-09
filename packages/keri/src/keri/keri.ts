import type { InceptEvent, KeyEvent, KeyEventAttachment, KeyEventMessage } from "../events/main.ts";
import { CounterCode, encodeBase64Int } from "../main-common.ts";

export interface WitnessSignature {
  aid: string;
  signature: string;
}

export interface KeyEventSignatures {
  controllers: string[];
  witnesses?: WitnessSignature[];
}

export function resolveKeyState(events: KeyEvent[]) {
  const inception = events[0] as InceptEvent;
  if (inception.t !== "icp") {
    throw new Error("First event was not inception");
  }

  return {
    s: "0",
    prefix: inception.d,
    event: inception.d,
    wits: inception.b,
    keys: inception.k,
    sith: inception.kt,
  };
}

export function serializeAttachment(attachments: KeyEventAttachment[]): string {
  let attachment = "";

  const sigs = attachments
    .filter((attachment) => attachment.code === CounterCode.ControllerIdxSigs)
    .map((attachment) => attachment.value);

  if (sigs.length > 0) {
    attachment += `${CounterCode.ControllerIdxSigs}${encodeBase64Int(sigs.length, 2)}${sigs.join("")}`;
  }

  const replayCouples = attachments
    .filter((attachment) => attachment.code === CounterCode.FirstSeenReplayCouples)
    .map((attachment) => attachment.value);

  if (replayCouples.length > 0) {
    attachment += `${CounterCode.FirstSeenReplayCouples}${encodeBase64Int(replayCouples.length, 2)}${replayCouples.join("")}`;
  }

  // TODO: This should not need to be floored
  const attachmentSize = Math.floor(new TextEncoder().encode(attachment).length / 4);
  const size = encodeBase64Int(attachmentSize, 2);

  return `${CounterCode.AttachmentGroup}${size}${attachment}`;
}

export interface Receipt {
  event: KeyEvent;
}

export async function submit(message: KeyEventMessage, witnessEndpoint: string): Promise<ReadableStream<Uint8Array>> {
  const url = new URL("/receipts", witnessEndpoint);

  const response = await fetch(url, {
    method: "POST",
    body: JSON.stringify(message.event),
    headers: {
      "Content-Type": "application/cesr+json",
      "CESR-ATTACHMENT": serializeAttachment(
        message.attachments.filter((a) => a.code === CounterCode.ControllerIdxSigs),
      ),
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to send event to wit ${witnessEndpoint}: ${response.status} ${response.statusText}`);
  }

  if (response.status !== 200) {
    throw new Error(`Failed to send event to wit ${witnessEndpoint}: ${response.status} ${response.statusText}`);
  }

  if (!response.body) {
    throw new Error(`Failed to send event to wit ${witnessEndpoint}: ${response.status} ${response.statusText}`);
  }

  return response.body;
}
