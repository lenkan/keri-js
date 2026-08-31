import { Attachments, decodeUtf8, encodeText, encodeUtf8, Message } from "../cesr/main.ts";

/**
 * The CESR stream a message travels as — the body frame followed by its
 * attachments. An empty attachment group is omitted entirely: KERIpy rejects a
 * zero-size `-VAA` as a parse error and drops the message with it.
 *
 * Pass `attachments` to frame a different set against the same body without
 * rebuilding it; `new Message(body, atc)` would re-serialize the whole body.
 */
export function encodeMessage(message: Message, attachments: Attachments = message.attachments): string {
  const frames = attachments.frames();
  return decodeUtf8(message.raw) + (frames.length > 1 ? encodeText(frames) : "");
}

/**
 * `Message.parse` reads only the body frame and discards whatever follows, so
 * the attachments are split off by byte offset. The stream `parse` from
 * `keri/cesr` handles both but is async, and every caller here is sync.
 */
export function decodeMessage(value: string): Message {
  const bytes = encodeUtf8(value);
  const message = Message.parse(bytes);
  if (message === null) {
    throw new Error("stored value is not a CESR message");
  }

  const attachments = Attachments.parse(bytes.slice(message.raw.length));
  if (attachments) {
    message.attachments = attachments;
  }
  return message;
}
