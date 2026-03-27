import { Matter, Message, VersionString } from "cesr";
import { saidify } from "./said.ts";

export const DUMMY_VERSION = VersionString.encode({ protocol: "KERI", legacy: true, kind: "JSON" });

export function formatDate(date: Date) {
  return date.toISOString().replace("Z", "000+00:00");
}

export function randomNonce() {
  return Matter.from(Matter.Code.Salt_128, crypto.getRandomValues(new Uint8Array(16))).text();
}

interface EncodeEventArgs {
  labels?: string[];
  protocol?: string;
  legacy?: boolean;
}

export function encodeEvent<T extends Record<string, unknown>>(data: T, args: EncodeEventArgs = {}): T & { v: string } {
  const labels = args.labels ?? ["d"];
  for (const label of labels) {
    if (!(label in data)) {
      throw new Error(`Input missing label '${label}'`);
    }

    (data as Record<string, unknown>)[label] = "#".repeat(44);
  }

  const message = new Message({
    v: VersionString.encode({ protocol: args.protocol ?? "KERI", legacy: args.legacy ?? true, kind: "JSON" }),
    ...data,
  });

  const result = saidify(message.body, labels);
  return result;
}
