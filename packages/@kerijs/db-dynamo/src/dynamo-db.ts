import {
  type ScanCommandInput,
  CreateTableCommand,
  DynamoDBClient,
  paginateScan,
  PutItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import type { KeyEvent, EventStore, KeyEventAttachment, KeyEventMessage, ListArgs } from "keri";

export interface DynamoEventStoreOptions {
  endpoint?: string;
  tableName: string;
  region?: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
  };
}

export class DynamoEventStore implements EventStore {
  #client: DynamoDBClient;
  tableName: string;

  constructor(options: DynamoEventStoreOptions) {
    this.#client = new DynamoDBClient({
      endpoint: options.endpoint,
      credentials: options.credentials,
      region: options.region,
    });
    this.tableName = options.tableName;
  }

  async init() {
    await this.#client.send(
      new CreateTableCommand({
        KeySchema: [
          { AttributeName: "pk", KeyType: "HASH" },
          { AttributeName: "sk", KeyType: "RANGE" },
        ],
        AttributeDefinitions: [
          { AttributeName: "pk", AttributeType: "S" },
          { AttributeName: "sk", AttributeType: "S" },
        ],
        TableName: this.tableName,
        ProvisionedThroughput: {
          ReadCapacityUnits: 1,
          WriteCapacityUnits: 1,
        },
      }),
    );
  }

  async saveEvent(event: KeyEvent) {
    const pk = `event#${event.d}`;
    const sk = "0";

    await this.#client.send(
      new PutItemCommand({ Item: marshall({ pk, sk, event, attachments: [] }), TableName: this.tableName }),
    );
  }

  async saveAttachment(id: string, attachment: KeyEventAttachment) {
    const pk = `event#${id}`;
    const sk = "0";

    await this.#client.send(
      new UpdateItemCommand({
        Key: marshall({ pk, sk }),
        TableName: this.tableName,
        UpdateExpression: "SET #attachments = list_append(#attachments, :attachment)",
        ExpressionAttributeNames: { "#attachments": "attachments" },
        ExpressionAttributeValues: marshall({ ":attachment": [attachment] }),
      }),
    );
  }

  async list(args: ListArgs = {}): Promise<KeyEventMessage[]> {
    const result: KeyEventMessage[] = [];
    const input: ScanCommandInput = {
      TableName: this.tableName,
    };

    const filterEntries = Object.entries(args);
    if (filterEntries.length > 0) {
      input.FilterExpression = filterEntries.map(([key]) => `event.#${key} = :${key}`).join(" AND ");
      input.ExpressionAttributeValues = filterEntries.reduce((acc, [key, value]) => {
        return { ...acc, [`:${key}`]: { S: value } };
      }, input.ExpressionAttributeValues);
      input.ExpressionAttributeNames = filterEntries.reduce((acc, [key]) => {
        return { ...acc, [`#${key}`]: key };
      }, input.ExpressionAttributeNames);
    }

    for await (const page of paginateScan({ client: this.#client, pageSize: 10 }, input)) {
      for (const item of page.Items ?? []) {
        const obj = unmarshall(item);

        result.push({
          event: obj.event,
          attachments: obj.attachments ?? [],
        });
      }
    }

    return result;
  }
}
