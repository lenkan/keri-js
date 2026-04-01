import { CreateTableCommand, DynamoDBClient, ResourceInUseException } from "@aws-sdk/client-dynamodb";

export function createDynamoClient(endpoint?: string) {
  if (!endpoint) {
    // Use default configuration which picks up credentials from environment variables or IAM roles
    return new DynamoDBClient();
  }

  const url = new URL(endpoint);

  return new DynamoDBClient({
    region: url.searchParams.get("region") || "no-region",
    endpoint,
    credentials: {
      accessKeyId: url.username,
      secretAccessKey: url.password,
    },
  });
}

export async function createTable(tableName: string, endpoint?: string): Promise<DynamoDBClient> {
  const client = createDynamoClient(endpoint);

  try {
    await client.send(
      new CreateTableCommand({
        TableName: tableName,
        KeySchema: [
          { AttributeName: "PK", KeyType: "HASH" },
          { AttributeName: "SK", KeyType: "RANGE" },
        ],
        AttributeDefinitions: [
          { AttributeName: "PK", AttributeType: "S" },
          { AttributeName: "SK", AttributeType: "S" },
        ],
        ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 },
      }),
    );
  } catch (error) {
    if (error instanceof ResourceInUseException) {
      // biome-ignore lint/suspicious/noConsole: expected in this context
      console.error("Table already exists, skipping creation.");
    } else {
      throw error;
    }
  }

  return client;
}
