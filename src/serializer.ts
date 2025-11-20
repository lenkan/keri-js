import {
  cesr,
  CountCode_10,
  encodeBase64Int,
  encodeCounter,
  encodeString,
  IndexCode,
  MatterCode,
} from "cesr/__unstable__";
import { type KeyEventReceipt, type KeyEventSeal } from "./events/event-store.ts";

export function encodeHexNumber(num: string) {
  return `${MatterCode.Salt_128}${encodeBase64Int(parseInt(num, 16), 22)}`;
}

export function serializeSignatures(sigs: string[], seal?: KeyEventSeal): string {
  const result: string[] = [];

  if (sigs && sigs.length > 0) {
    if (seal && seal.i && seal.s && seal.d) {
      result.push(
        encodeCounter({
          code: CountCode_10.TransIdxSigGroups,
          count: 1,
        }),
      );

      result.push(seal.i);
      result.push(encodeHexNumber(seal.s));
      result.push(seal.d);
    }

    result.push(encodeCounter({ code: CountCode_10.ControllerIdxSigs, count: sigs.length }));
    result.push(...sigs);
  }

  return result.join("");
}

export function serializeWitnessSignatures(receipts: KeyEventReceipt[], backers: string[]): string[] {
  const result: string[] = [];

  if (receipts.length > 0) {
    result.push(encodeCounter({ code: CountCode_10.WitnessIdxSigs, count: receipts.length }));

    for (const sig of receipts) {
      const signature = cesr.decodeMatter(sig.signature);
      const index = backers.indexOf(sig.backer);
      if (index === -1) {
        throw new Error(`Unknown backer ${sig.backer}`);
      }

      result.push(
        cesr.encodeIndexer({
          code: getIndexedCode(signature.code),
          raw: signature.raw,
          index: index,
        }),
      );
    }
  }

  return result;
}

export function serializeReceipts(receipts: KeyEventReceipt[]): string {
  const result: string[] = [];

  if (receipts.length > 0) {
    result.push(encodeCounter({ code: CountCode_10.NonTransReceiptCouples, count: receipts.length }));
    result.push(...receipts.map((receipt) => receipt.backer + receipt.signature));
  }

  return result.join("");
}

export function serializePathedGroup(path: string[], attachments: string[]) {
  const result: string[] = [];

  result.push(encodeString(`-${path.join("-")}`));
  result.push(...attachments);

  return (
    encodeCounter({
      code: CountCode_10.PathedMaterialCouples,
      count: result.join("").length / 4,
    }) + result.join("")
  );
}

export function serializeAttachments(attachments: string[]): string {
  const result = attachments.join("");
  return `${encodeCounter({ code: CountCode_10.AttachmentGroup, count: result.length / 4 })}${result}`;
}

export function serializeEventSeal(seal: KeyEventSeal) {
  return [
    encodeCounter({ code: CountCode_10.SealSourceTriples, count: 1 }),
    seal.i,
    encodeHexNumber(seal.s),
    seal.d,
  ].join("");
}

export function serializeDigestSeal(seal: KeyEventSeal) {
  return [encodeCounter({ code: CountCode_10.SealSourceCouples, count: 1 }), encodeHexNumber(seal.s), seal.d].join("");
}

export function getIndexedCode(code: string): string {
  switch (code) {
    case MatterCode.Ed25519_Sig:
      return IndexCode.Ed25519_Sig;
    case MatterCode.Ed448_Sig:
      return IndexCode.Ed448_Sig;
    default:
      throw new Error(`Unsupported indexed signature type: ${code}`);
  }
}
