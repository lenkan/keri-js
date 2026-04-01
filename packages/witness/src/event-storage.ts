import { type DynamoDBClient, PutItemCommand, paginateScan } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { Message } from "cesr";
import type { KeyEventBody } from "keri";
import type { WitnessEvent } from "./witness.ts";

export interface EventStorageOptions {
  client: DynamoDBClient;
  tableName: string;
}

export interface ListEventArgs {
  i: string;
}

export class EventStorage {
  client: DynamoDBClient;
  tableName: string;

  constructor(options: EventStorageOptions) {
    this.client = options.client;
    this.tableName = options.tableName;
  }

  async saveEvent(event: WitnessEvent): Promise<void> {
    const body = event.message.body as KeyEventBody;
    await this.client.send(
      new PutItemCommand({
        TableName: this.tableName,
        Item: marshall({
          PK: `event#${body.d}`,
          SK: `event#${body.s}`,
          i: body.i,
          sad: JSON.stringify(body),
          sigs: event.message.attachments.ControllerIdxSigs,
          receipts: event.message.attachments.NonTransReceiptCouples,
          timestamp: event.timestamp.toISOString(),
        }),
      }),
    );
  }

  async listEvents(args: ListEventArgs): Promise<WitnessEvent[]> {
    const events: WitnessEvent[] = [];

    for await (const page of paginateScan(
      { client: this.client },
      {
        TableName: this.tableName,
        FilterExpression: "i = :i",
        ExpressionAttributeValues: {
          ":i": { S: args.i },
        },
      },
    )) {
      for (const item of page.Items ?? []) {
        const u = unmarshall(item);
        const body = JSON.parse(u.sad) as KeyEventBody;
        const message = new Message(body, {
          ControllerIdxSigs: u.sigs ?? [],
          NonTransReceiptCouples: u.receipts ?? [],
        });
        events.push({
          message,
          timestamp: new Date(Date.parse(u.timestamp)),
        });
      }
    }

    return events;
  }
}
