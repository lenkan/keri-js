/** biome-ignore-all lint/suspicious/noConsole: worker entrypoint */

import { DurableObject } from "cloudflare:workers";
import { Mailbox } from "@keri-js/infra/mailbox";
import { createPortalRouter } from "@keri-js/infra/portal";
import { type Database, type Params, type Row, SqliteControllerStorage } from "@keri-js/infra/sqlite";
import { Witness } from "@keri-js/infra/witness";
import { decodeSeed } from "./seed.ts";

/**
 * The sync `Database` interface over Durable Object SQLite — which is also
 * synchronous, so the whole sqlite storage layer runs here unchanged. Named
 * `$param` bindings become positional `?` in occurrence order.
 */
class DurableObjectDatabase implements Database {
  readonly #storage: DurableObjectStorage;
  readonly #sql: SqlStorage;

  constructor(storage: DurableObjectStorage) {
    this.#storage = storage;
    this.#sql = storage.sql;
  }

  #bind(sql: string, params: Params = {}): { query: string; values: (string | number | null)[] } {
    const values: (string | number | null)[] = [];
    const query = sql.replace(/\$(\w+)/g, (_match, name: string) => {
      if (!(name in params)) {
        throw new Error(`Missing parameter $${name}`);
      }
      const value = params[name];
      if (value instanceof Uint8Array) {
        throw new Error(`Unsupported Uint8Array parameter $${name}`);
      }
      values.push(value);
      return "?";
    });
    return { query, values };
  }

  execute(sql: string, params?: Params): void {
    const { query, values } = this.#bind(sql, params);
    this.#sql.exec(query, ...values);
  }

  *iterate(sql: string, params?: Params): Iterable<Row> {
    const { query, values } = this.#bind(sql, params);
    for (const row of this.#sql.exec(query, ...values)) {
      yield row as Row;
    }
  }

  transaction<T>(fn: () => T): T {
    // Raw BEGIN/COMMIT is forbidden in DO SQLite; this is its blessed form.
    return this.#storage.transactionSync(fn);
  }
}

/**
 * The portal's stateful side: mailbox (enrollment, store-and-forward, polls,
 * enrolled-AID OOBIs), receipts, and query replay — one named instance owning
 * the SQLite storage, so every append is serialized by the runtime. That
 * serialization is the property the issuer's KEL will rely on when it moves
 * in here.
 */
export class PortalStore extends DurableObject<Env> {
  readonly #storage: SqliteControllerStorage;
  readonly #routers = new Map<string, Promise<(request: Request) => Promise<Response>>>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // The storage constructor runs the migrations; DO SQLite is synchronous,
    // so this completes before the first request is admitted.
    this.#storage = new SqliteControllerStorage(new DurableObjectDatabase(ctx.storage));
  }

  #router(url: string): Promise<(request: Request) => Promise<Response>> {
    let router = this.#routers.get(url);

    if (!router) {
      const seed = this.env.VERIFIER_SEED;
      if (!seed) {
        console.warn("VERIFIER_SEED is not set; the portal store identity will not match the worker's");
      }

      // Same seed as the worker's Verifier, so both faces ARE the portal
      // identity: the mailbox holds enrolled users' mail, the witness face
      // receipts (KERIpy refuses a KEL with witnesses listed and toad 0, so an
      // issuer naming the portal as witness needs real receipts).
      const privateKey = seed ? decodeSeed(seed) : undefined;
      router = Promise.all([
        Mailbox.create({ storage: this.#storage, privateKey, url }),
        Witness.create({ storage: this.#storage, privateKey, url }),
      ]).then(([mailbox, witness]) => createPortalRouter(mailbox, witness, this.#storage, { logger: console }));
      this.#routers.set(url, router);
    }

    return router;
  }

  async fetch(request: Request): Promise<Response> {
    const url = this.env.VERIFIER_URL ?? new URL(request.url).origin;
    const router = await this.#router(url);
    return router(request);
  }
}
