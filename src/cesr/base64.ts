export const Base64 = (function () {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const map = alphabet.split("");

  return {
    fromInt(value: number, l = 1): string {
      let i = value;
      let result = "";
      while (l != 0) {
        result = map[i % 64] + result;
        i = Math.floor(i / 64);
        if (i == 0) {
          break;
        }
      }

      const x = l - result.length;
      for (let i = 0; i < x; i++) {
        result = "A" + result;
      }

      return result;
    },
    toInt(value: string) {
      return value
        .split("")
        .reverse()
        .reduce((result, character, index) => {
          const value = alphabet.indexOf(character);
          const factor = 64 ** index;
          return result + value * factor;
        }, 0);
    },
  };
})();

export function encodeBase64Url(buffer: Uint8Array) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+/, "");
}

export function decodeBase64Url(input: string): Uint8Array {
  if (!(typeof input === "string")) {
    throw new TypeError("`input` must be a string.");
  }

  const n = input.length % 4;
  const padded = input + "=".repeat(n > 0 ? 4 - n : n);
  const base64String = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(base64String, "base64"));
}
