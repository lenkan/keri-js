import type { InceptEvent, KeyEvent } from "../events/main.ts";
import { CounterCode, encodeBase64Int } from "../main-common.ts";

export interface WitnessSignature {
  aid: string;
  signature: string;
}

export interface KeyEventSignatures {
  controllers: string[];
  witnesses?: WitnessSignature[];
}

export interface KeyEventMessage {
  event: KeyEvent;
  signatures: KeyEventSignatures;
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

export function serializeAttachment(message: KeyEventMessage): string {
  const sigs = message.signatures.controllers;

  const controllerSigs = `${CounterCode.ControllerIdxSigs}${encodeBase64Int(message.signatures.controllers.length, 2)}${sigs.join("")}`;

  const attachmentSize = new TextEncoder().encode(controllerSigs).length / 4;
  const attachment = `${CounterCode.AttachmentGroup}${encodeBase64Int(attachmentSize, 2)}${controllerSigs}`;

  return attachment;
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
      "CESR-ATTACHMENT": serializeAttachment(message),
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
