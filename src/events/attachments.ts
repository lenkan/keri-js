import { cesr, CountCode_10, Parser } from "cesr/__unstable__";
import { type DigestSeal, type KeyEventReceipt, type KeyEventSeal } from "./event-store.ts";
import { encodeHexNumber } from "../serializer.ts";

function serialize(attachments: AttachmentsInit): string {
  const atc: string[] = [];

  if (attachments.sigs && attachments.sigs.length > 0) {
    const seal = attachments.seal;

    if (seal) {
      if ("i" in seal && seal.i && seal.s && seal.d) {
        atc.push(
          cesr.encodeCounter({
            code: CountCode_10.TransIdxSigGroups,
            count: 1,
          }),
        );

        atc.push(seal.i);
        atc.push(encodeHexNumber(seal.s));
        atc.push(seal.d);
      }

      // TODO
      // elif isinstance(seal, SealLast):
      //     atc.extend(Counter(Codens.TransLastIdxSigGroups, count=1,
      //                        version=kering.Vrsn_1_0).qb64b)
      //     atc.extend(seal.i.encode("utf-8"))
    }

    atc.push(
      cesr.encodeCounter({
        code: CountCode_10.ControllerIdxSigs,
        count: attachments.sigs.length,
      }),
      ...attachments.sigs,
    );
  }

  if (attachments.source) {
    if ("i" in attachments.source && attachments.source.i && attachments.source.s && attachments.source.d) {
      atc.push(
        cesr.encodeCounter({
          code: CountCode_10.SealSourceTriples,
          count: 1,
        }),
        attachments.source.i,
        encodeHexNumber(attachments.source.s),
        attachments.source.d,
      );
    } else if ("s" in attachments.source && attachments.source.s && attachments.source.d) {
      atc.push(
        cesr.encodeCounter({
          code: CountCode_10.SealSourceCouples,
          count: 1,
        }),
        encodeHexNumber(attachments.source.s),
        attachments.source.d,
      );
    }
  }

  if (attachments.receipts && attachments.receipts.length > 0) {
    atc.push(
      cesr.encodeCounter({
        code: CountCode_10.NonTransReceiptCouples,
        count: attachments.receipts.length,
      }),
      ...attachments.receipts.map((receipt) => receipt.backer + receipt.signature),
    );
  }

  if (attachments.wigs && attachments.wigs.length > 0) {
    atc.push(
      cesr.encodeCounter({
        code: CountCode_10.WitnessIdxSigs,
        count: attachments.wigs.length,
      }),
      ...attachments.wigs,
    );
  }

  for (const [path, pathed] of Object.entries(attachments.nested ?? {})) {
    const nested: string[] = [];
    nested.push(cesr.encodeString(path));
    nested.push(serialize(pathed ?? {}));

    if (path === undefined) {
      throw new Error("Path in pathed material cannot be undefined");
    }

    atc.push(
      cesr.encodeCounter({
        code: CountCode_10.PathedMaterialCouples,
        count: nested.join("").length / 4,
      }),
    );

    atc.push(...nested);
  }

  if (attachments.firstSeen && attachments.firstSeen.length > 0) {
    atc.push(
      cesr.encodeCounter({
        code: CountCode_10.FirstSeenReplayCouples,
        count: 1,
      }),
      ...attachments.firstSeen.map((fs) => {
        return `${encodeHexNumber(fs.s)}${cesr.encodeDate(fs.timestamp)}`;
      }),
    );
  }

  const result = atc.join("");
  const count = result.length / 4;

  if (attachments.grouped) {
    return cesr.encodeAttachmentsV1(count) + result;
  }

  return result;
}

export interface AttachmentsInit {
  grouped?: boolean;
  sigs?: string[];
  wigs?: string[];
  receipts?: KeyEventReceipt[];
  seal?: KeyEventSeal | DigestSeal | null;
  source?: KeyEventSeal | DigestSeal | null;
  nested?: Record<string, AttachmentsInit>;
  firstSeen?: FirstSeenCouple[];
}

// def messagize(serder, *, sigers=None, seal=None, wigers=None, cigars=None,
//               pipelined=False):

export interface FirstSeenCouple {
  s: string;
  timestamp: Date;
}

export interface PathedMaterial {
  path: string[];
  grouped?: boolean;
  attachment?: AttachmentsInit;
}

export interface SealedSignatures {
  seal: KeyEventSeal;
  sigs: string[];
}

export class Attachments implements Required<AttachmentsInit> {
  #data: Required<AttachmentsInit>;

  constructor(init?: AttachmentsInit) {
    this.#data = {
      grouped: init?.grouped ?? true,
      sigs: init?.sigs ?? [],
      wigs: init?.wigs ?? [],
      seal: init?.seal ?? null,
      source: init?.source ?? null,
      receipts: init?.receipts ?? [],
      nested: init?.nested ?? {},
      firstSeen: init?.firstSeen ?? [],
    };
  }

  get grouped(): boolean {
    return this.#data.grouped;
  }

  get source(): KeyEventSeal | DigestSeal | null {
    return this.#data.source ?? null;
  }

  get firstSeen(): FirstSeenCouple[] {
    return this.#data.firstSeen;
  }

  get sigs(): string[] {
    return this.#data.sigs;
  }

  get wigs(): string[] {
    return this.#data.wigs;
  }

  get receipts(): KeyEventReceipt[] {
    return this.#data.receipts;
  }

  get seal(): KeyEventSeal | DigestSeal | null {
    return this.#data.seal ?? null;
  }

  get nested(): Record<string, AttachmentsInit> {
    return this.#data.nested;
  }

  static parse(attachments: string): Attachments {
    if (typeof attachments !== "string") {
      throw new Error("Attachments must be a string");
    }

    return this.fromData(new TextEncoder().encode(attachments));
  }

  static fromData(data: Uint8Array): Attachments {
    const parser = new Parser();
    const iterator = parser.parse(data);
    const init: AttachmentsInit = {};

    let result = iterator.next();
    while (!result.done) {
      const frame = result.value;

      if (frame.type === "message") {
        // Skip message
        result = iterator.next();
        continue;
      }

      const group = cesr.decodeCounter(frame.text);

      switch (group.code) {
        case CountCode_10.ControllerIdxSigs: {
          while (group.count > 0) {
            init.sigs = init.sigs || [];
            init.sigs.push(iterator.next().value.text);
            group.count--;
          }
          break;
        }
        case CountCode_10.WitnessIdxSigs: {
          while (group.count > 0) {
            init.wigs = init.wigs || [];
            init.wigs.push(iterator.next().value.text);
            group.count--;
          }
          break;
        }
        case CountCode_10.NonTransReceiptCouples: {
          while (group.count > 0) {
            init.receipts = init.receipts || [];
            init.receipts.push({
              backer: iterator.next().value.text,
              signature: iterator.next().value.text,
            });
            group.count--;
          }
          break;
        }
        case CountCode_10.FirstSeenReplayCouples: {
          while (group.count > 0) {
            init.firstSeen = init.firstSeen || [];
            init.firstSeen.push({
              s: iterator.next().value.text,
              timestamp: new Date(iterator.next().value.text),
            });
            group.count--;
          }
          break;
        }
        case CountCode_10.SealSourceTriples: {
          if (group.count !== 1) {
            throw new Error("SealSourceTriples must have count of 1");
          }
          init.source = {
            i: iterator.next().value.text,
            s: parseInt(iterator.next().value.text, 16).toString(16),
            d: iterator.next().value.text,
          };
          break;
        }

        case CountCode_10.SealSourceCouples: {
          if (group.count !== 1) {
            throw new Error("SealSourceCouples must have count of 1");
          }
          init.source = {
            s: parseInt(iterator.next().value.text, 16).toString(16),
            d: iterator.next().value.text,
          };
          break;
        }
      }

      result = iterator.next();
    }

    return new Attachments(init);
  }

  toString(): string {
    return serialize(this.#data);
  }
}
// def cloneEvtMsg(self, pre, fn, dig):
//     """
//     Clones Event as Serialized CESR Message with Body and attached Foot

//     Parameters:
//         pre (bytes): identifier prefix of event
//         fn (int): first seen number (ordinal) of event
//         dig (bytes): digest of event

//     Returns:
//         bytearray: message body with attachments
//     """
//     msg = bytearray()  # message
//     atc = bytearray()  # attachments
//     dgkey = dbing.dgKey(pre, dig)  # get message
//     if not (raw := self.getEvt(key=dgkey)):
//         raise kering.MissingEntryError("Missing event for dig={}.".format(dig))
//     msg.extend(raw)

//     # add indexed signatures to attachments
//     if not (sigs := self.getSigs(key=dgkey)):
//         raise kering.MissingEntryError("Missing sigs for dig={}.".format(dig))
//     atc.extend(core.Counter(code=core.Codens.ControllerIdxSigs,
//                             count=len(sigs), version=kering.Vrsn_1_0).qb64b)
//     for sig in sigs:
//         atc.extend(sig)

//     # add indexed witness signatures to attachments
//     if wigs := self.getWigs(key=dgkey):
//         atc.extend(core.Counter(code=core.Codens.WitnessIdxSigs,
//                                 count=len(wigs), version=kering.Vrsn_1_0).qb64b)
//         for wig in wigs:
//             atc.extend(wig)

//     # add authorizer (delegator/issuer) source seal event couple to attachments
//     couple = self.getAes(dgkey)
//     if couple is not None:
//         atc.extend(core.Counter(code=core.Codens.SealSourceCouples,
//                                 count=1, version=kering.Vrsn_1_0).qb64b)
//         atc.extend(couple)

//     # add trans endorsement quadruples to attachments not controller
//     # may have been originally key event attachments or receipted endorsements
//     if quads := self.getVrcs(key=dgkey):
//         atc.extend(core.Counter(code=core.Codens.TransReceiptQuadruples,
//                                 count=len(quads), version=kering.Vrsn_1_0).qb64b)
//         for quad in quads:
//             atc.extend(quad)

//     # add nontrans endorsement couples to attachments not witnesses
//     # may have been originally key event attachments or receipted endorsements
//     if coups := self.getRcts(key=dgkey):
//         atc.extend(core.Counter(code=core.Codens.NonTransReceiptCouples,
//                                 count=len(coups), version=kering.Vrsn_1_0).qb64b)
//         for coup in coups:
//             atc.extend(coup)

//     # add first seen replay couple to attachments
//     if not (dts := self.getDts(key=dgkey)):
//         raise kering.MissingEntryError("Missing datetime for dig={}.".format(dig))
//     atc.extend(core.Counter(code=core.Codens.FirstSeenReplayCouples,
//                             count=1, version=kering.Vrsn_1_0).qb64b)
//     atc.extend(core.Number(num=fn, code=core.NumDex.Huge).qb64b)  # may not need to be Huge
//     atc.extend(coring.Dater(dts=bytes(dts)).qb64b)

//     # prepend pipelining counter to attachments
//     if len(atc) % 4:
//         raise ValueError("Invalid attachments size={}, nonintegral"
//                          " quadlets.".format(len(atc)))
//     pcnt = core.Counter(code=core.Codens.AttachmentGroup,
//                         count=(len(atc) // 4), version=kering.Vrsn_1_0).qb64b
//     msg.extend(pcnt)
//     msg.extend(atc)
//     return msg

// def messagize(serder, *, sigers=None, seal=None, wigers=None, cigars=None,
//               pipelined=False):
//     """
//     Attaches indexed signatures from sigers and/or cigars and/or wigers to
//     KERI message data from serder
//     Parameters:
//         serder (SerderKERI): instance containing the event
//         sigers (list): of Siger instances (optional) to create indexed signatures
//         seal (Union[SealEvent, SealLast]): optional if sigers and
//             If SealEvent use attachment group code TransIdxSigGroups plus attach
//                 triple pre+snu+dig made from (i,s,d) of seal plus ControllerIdxSigs
//                 plus attached indexed sigs in sigers
//             Else If SealLast use attachment group code TransLastIdxSigGroups plus
//                 attach uniple pre made from (i,) of seal plus ControllerIdxSigs
//                 plus attached indexed sigs in sigers
//             Else use ControllerIdxSigs plus attached indexed sigs in sigers
//         wigers (list): optional list of Siger instances of witness index signatures
//         cigars (list): optional list of Cigars instances of non-transferable non indexed
//             signatures from  which to form receipt couples.
//             Each cigar.vefer.qb64 is pre of receiptor and cigar.qb64 is signature
//         pipelined (bool), True means prepend pipelining count code to attachemnts
//             False means to not prepend pipelining count code

//     Returns: bytearray KERI event message
//     """
//     msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
//     atc = bytearray()  # attachment

//     if not (sigers or cigars or wigers):
//         raise ValueError("Missing attached signatures on message = {}."
//                          "".format(serder.ked))

//     if sigers:
//         if isinstance(seal, SealEvent):
//             atc.extend(Counter(Codens.TransIdxSigGroups, count=1,
//                                     version=kering.Vrsn_1_0).qb64b)
//             atc.extend(seal.i.encode("utf-8"))
//             atc.extend(Seqner(snh=seal.s).qb64b)
//             atc.extend(seal.d.encode("utf-8"))

//         elif isinstance(seal, SealLast):
//             atc.extend(Counter(Codens.TransLastIdxSigGroups, count=1,
//                                version=kering.Vrsn_1_0).qb64b)
//             atc.extend(seal.i.encode("utf-8"))

//         atc.extend(Counter(Codens.ControllerIdxSigs, count=len(sigers),
//                            version=kering.Vrsn_1_0).qb64b)
//         for siger in sigers:
//             atc.extend(siger.qb64b)

//     if wigers:
//         atc.extend(Counter(Codens.WitnessIdxSigs, count=len(wigers),
//                            version=kering.Vrsn_1_0).qb64b)
//         for wiger in wigers:
//             if wiger.verfer and wiger.verfer.code not in NonTransDex:
//                 raise ValueError("Attempt to use tranferable prefix={} for "
//                                  "receipt.".format(wiger.verfer.qb64))
//             atc.extend(wiger.qb64b)

//     if cigars:
//         atc.extend(Counter(Codens.NonTransReceiptCouples, count=len(cigars),
//                            version=kering.Vrsn_1_0).qb64b)
//         for cigar in cigars:
//             if cigar.verfer.code not in NonTransDex:
//                 raise ValueError("Attempt to use tranferable prefix={} for "
//                                  "receipt.".format(cigar.verfer.qb64))
//             atc.extend(cigar.verfer.qb64b)
//             atc.extend(cigar.qb64b)

//     if pipelined:
//         if len(atc) % 4:
//             raise ValueError("Invalid attachments size={}, nonintegral"
//                              " quadlets.".format(len(atc)))
//         msg.extend(Counter(Codens.AttachmentGroup,
//                            count=(len(atc) // 4), version=kering.Vrsn_1_0).qb64b)

//     msg.extend(atc)
//     return msg
