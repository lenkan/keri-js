import { Counter } from "../counter.ts";
import { type Frame, resolveQuadletCount } from "../frame.ts";
import { Matter } from "../matter.ts";

export type GenericMapGroupInit = Record<string, unknown>;

/**
 * CESR Generic Map
 */
export class GenericMapGroup {
  #map: Map<string, unknown>;

  constructor(init: GenericMapGroupInit) {
    this.#map = new Map<string, unknown>(Object.entries(init));
  }

  frames(): Frame[] {
    const frames: Frame[] = [];

    for (const [key, value] of this.#map.entries()) {
      frames.push(Matter.primitive.tag(key));

      switch (typeof value) {
        case "string":
          frames.push(Matter.primitive.string(value));
          break;
        case "number":
          frames.push(Matter.primitive.decimal(value));
          break;
        case "boolean":
          if (value) {
            frames.push(Matter.from(Matter.Code.Yes, new Uint8Array()));
          } else {
            frames.push(Matter.from(Matter.Code.No, new Uint8Array()));
          }
          break;
        case "object": {
          if (!Array.isArray(value) && value !== null && !(value instanceof Date)) {
            frames.push(...new GenericMapGroup({ ...value }).frames());
          } else {
            throw new Error(`Unsupported object type for key ${key}: ${JSON.stringify(value)}`);
          }
          break;
        }
        default:
          throw new Error(`Unsupported value type ${typeof value} for key ${key}`);
      }
    }

    const size = frames.reduce((acc, frame) => acc + resolveQuadletCount(frame), 0);
    return [Counter.v2.GenericMapGroup(size), ...frames];
  }

  static from(init: GenericMapGroupInit): GenericMapGroup {
    return new GenericMapGroup(init);
  }
}
