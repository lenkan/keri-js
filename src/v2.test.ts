import test from "node:test";
import { keri, type InceptEvent, type InceptEventInit, type InteractEvent } from "./main.ts";
import { cesr, MatterCode } from "cesr/__unstable__";

export class KeyEvent<T extends InceptEvent | InteractEvent> {
  readonly data: Readonly<T>;

  constructor(data: T) {
    this.data = Object.freeze(data);
  }

  get raw(): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(this.data));
  }

  static incept(args: InceptEventInit): KeyEvent<InceptEvent> {
    return new KeyEvent(keri.incept(args));
  }
}

test("sample test", () => {
  const key = cesr.encodeMatter({
    code: MatterCode.Ed25519,
    raw: crypto.getRandomValues(new Uint8Array(32)),
  });

  const event = KeyEvent.incept({ k: [key] });
});
