import { createTable } from "./dynamo-client.ts";

await createTable(process.env.DYNAMODB_ENDPOINT ?? "", process.env.DYNAMODB_TABLE_NAME);
