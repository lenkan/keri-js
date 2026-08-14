# keri

KERI (Key Event Receipt Infrastructure) for JavaScript. Creates key events, messages and
credentials, and verifies key event logs and ACDC credentials.

## Install

```sh
npm install keri
```

Requires Node.js 22 or later. The root entry point runs in Deno and in the browser; the
`sqlite-storage`, `witness`, `mailbox` and `nodejs-utils` subpaths are Node.js only.

## Usage

```ts
import { Controller } from "keri";
import { NodeSqliteDatabase, SqliteControllerStorage } from "keri/sqlite-storage";
import { DatabaseSync } from "node:sqlite";

const controller = new Controller({
  storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
});

await controller.introduce(witnessOobi);
const { id } = await controller.incept({ wits: [witnessAid], toad: 1 });
```

Verify credentials without a controller:

```ts
import { EventIndex, verifyCredentials } from "keri";
```

## Entry points

| Import | Contents |
| --- | --- |
| `keri` | controller, key events, credentials, verification |
| `keri/sqlite-storage` | SQLite-backed storage via `node:sqlite` |
| `keri/witness` | witness node and its HTTP router |
| `keri/mailbox` | mailbox server and its HTTP router |
| `keri/nodejs-utils` | `node:http` listener adapter |
