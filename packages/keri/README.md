# keri

KERI (Key Event Receipt Infrastructure) for JavaScript. Creates key events, messages and
credentials, and verifies key event logs and ACDC credentials.

The package is platform, transport and storage agnostic: it operates on messages and byte
streams and performs no I/O. Bring your own network and database.

## Install

```sh
npm install keri
```

Requires Node.js 22 or later. Runs unchanged in Deno and in the browser.

## Usage

Build a key event log from a CESR byte stream — anything async-iterable, whether it came from
a file, an HTTP response or a socket:

```ts
import { KeyEventLog } from "keri";

const response = await fetch(oobi);
const log = await KeyEventLog.parse(response.body);

console.log(log.state.signingKeys);
```

Create and sign key events:

```ts
import { keri } from "keri";

const { privateKey, publicKey, publicKeyDigest } = keri.utils.generateKeyPair();
const event = keri.incept({ signingKeys: [publicKey], nextKeys: [keri.utils.digest(nextKey)] });
const signatures = await keri.utils.sign(event.raw, [privateKey]);
```

Verify credentials from a stream:

```ts
import { EventIndex, verifyCredentials } from "keri";

const index = await EventIndex.parse(stream);
const results = verifyCredentials(index);
```

## Entry points

| Import | Contents |
| --- | --- |
| `keri` | key events, key event logs, credentials, verification |
| `cesr` | the CESR encoding and stream parser this package builds on |

Reference implementations of a witness, a mailbox and a controller — the parts that need HTTP
and a database — live in this repository under `apps/` and are not published.
