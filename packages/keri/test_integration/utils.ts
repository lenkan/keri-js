import { DatabaseSync } from "node:sqlite";
import { NodeSqliteDatabase, SqliteControllerStorage } from "#keri/sqlite-storage";
import { Controller } from "../src/controller/controller.ts";

export interface Witness {
  aid: string;
  url: string;
  oobi: string;
}

export async function resolveWitness(host: string): Promise<Witness> {
  const url = new URL("/oobi", host);

  const response = await fetch(url, {
    method: "GET",
  });

  const aid = response.headers.get("Keri-Aid");
  if (!aid) {
    throw new Error(`Failed to resolve witness: Missing Keri-Aid header`);
  }

  if (!response.ok) {
    throw new Error(`Failed to resolve witness: ${response.status} ${response.statusText}`);
  }

  return {
    aid: aid,
    url: host,
    oobi: url.toString(),
  };
}

export function createController() {
  const controller = new Controller({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });

  return controller;
}
