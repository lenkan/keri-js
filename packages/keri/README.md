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

Message constructors are grouped by protocol: `KeyEvent` (KEL), `TransactionEvent` (registry TEL),
`RoutedEvent` (`exn`/`qry`/`rpy`) and `Credential` (ACDC).

### Create and sign key events

```ts
import { ed25519Signer, generateKeyPair, KeyEvent, nextKeyDigest, signEvent } from "keri";

const current = generateKeyPair();
const next = generateKeyPair();

const icp = KeyEvent.incept({
  signingKeys: [current.publicKey],
  nextKeyDigests: [next.publicKeyDigest],
});

await signEvent(icp, [ed25519Signer(current.privateKey)]);
```

`nextKeyDigests` takes digests of the next keys, not the keys themselves. Use
`nextKeyDigest(publicKey)` when rotating with a key you already hold.

Keys that never leave an HSM or a non-extractable WebCrypto `CryptoKey` implement `Signer`
directly:

```ts
import type { Signer } from "keri";

const signer: Signer = {
  publicKey,
  sign: (payload) => hsm.sign(payload), // returns a CESR-encoded signature
};
```

### Read a key event log from a stream

Anything async-iterable works, whether it came from a file, an HTTP response or a socket:

```ts
import { KeyEventLog } from "keri";

const response = await fetch(oobi);
const log = await KeyEventLog.parse(response.body);

console.log(log.state.signingKeys);
```

### Verify a stream

Parsing is streaming and syntax-only; verification needs the settled set, so the two are separate
steps. `verify` never throws on a verification failure — a message that does not check out is a
normal result.

```ts
import { collect, verify } from "keri";

const report = verify(await collect(stream));

report.identifiers; // per-AID key state
report.registries;  // per-registry status
report.credentials; // per-credential checks
report.problems;    // every failure, flattened
```

### Build a credential

```ts
import { Credential, TransactionEvent } from "keri";

const vcp = TransactionEvent.incept({ ii: issuerAid });

const acdc = Credential.from({
  i: issuerAid,
  ri: vcp.body.i,
  s: schemaSaid,
  a: { i: holderAid, LEI: "5493001KJTIIGC8Y1R17" },
  r: {},
});

const iss = TransactionEvent.issue({ i: acdc.body.d, ri: vcp.body.i });
```

## Protocol versions

Constructors emit KERI v1 by default. Pass `version: 2` to emit v2:

```ts
KeyEvent.incept({ signingKeys, nextKeyDigests, version: 2 });
```

`parse`, `collect` and `verify` accept either version without configuration.

## Entry points

| Import | Contents |
| --- | --- |
| `keri` | key events, key event logs, credentials, verification |
| `cesr` | the CESR encoding and stream parser this package builds on, re-exported from `keri` |

Reference implementations of a witness, a mailbox, a controller and a verifier — the parts that
need HTTP and a database — live in this repository under `packages/keri-infra` and `apps/`, and are
not published.
