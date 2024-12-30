import { Base64 } from "../cesr/base64.ts";

export interface Version {
  protocol: string;
  format: string;
  version: string;
  size: number;
}

// PPPPvvKKKKllllll_
const LEGACY_MATCH = /^[A-Z]{4}[0-9]{2}[A-Z]{4}.*$/;

// PPPPVVVKKKKBBBB.
const MATCH = /^[A-Z]{4}[0-9]{3}[A-Z]{4}.*$/;

export function parseVersion(data: Uint8Array | string): Version {
  if (typeof data !== "string") {
    return parseVersion(new TextDecoder().decode(data.slice(6, 23)));
  }

  const value = data;
  if (LEGACY_MATCH.test(value)) {
    const protocol = value.slice(0, 4);
    const version = value.slice(4, 6);
    const format = value.slice(6, 10);
    const size = parseInt(value.slice(10, 16), 16);

    return {
      protocol,
      version,
      format,
      size,
    };
  } else if (MATCH.test(value)) {
    const protocol = value.slice(0, 4);
    const version = value.slice(4, 7);
    const format = value.slice(7, 11);
    const size = Base64.toInt(value.slice(12, 15));

    return {
      protocol,
      version,
      format,
      size,
    };
  }

  throw new Error(`Unexpected version string ${value}`);
}
