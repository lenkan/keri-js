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

Each group is an ES module namespace, so you can take it whole from the root or a function at a
time from its subpath. Both name the same function:

```ts
import { KeyEvent } from "keri";
import { incept } from "keri/key-events";

KeyEvent.incept === incept; // true
```

Taking them from the subpath lets a bundler drop what you don't use. Both `KeyEvent.incept` and
`TransactionEvent.incept` are called `incept` — one is a KEL inception, the other a registry's — so
the grouping is what tells them apart.

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

const acdc = Credential.create({
  i: issuerAid,
  ri: vcp.body.i,
  s: schemaSaid,
  a: { i: holderAid, LEI: "5493001KJTIIGC8Y1R17" },
  r: {},
});

const iss = TransactionEvent.issue({ i: acdc.body.d, ri: vcp.body.i });
```

## Protocol versions

Constructors emit KERI v1. Reading is version-tolerant: `parse`, `collect` and `verify` accept any
version string a message carries, and SAIDs are recomputed against the version the body declares —
minor version and serialization kind included.

Writing v2 is not supported yet. It needs CESR attachment groups to be emitted with v2 counter
codes, which `cesr` does not do.

## Entry points

| Import | Contents |
| --- | --- |
| `keri` | everything: the four namespaces, key event logs, verification, signing, and the CESR types re-exported from `cesr` |
| `keri/key-events` | `incept`, `interact`, `rotate`, `delegatedIncept`, `delegatedRotate`, `receipt`, `isKeyEvent` |
| `keri/transaction-events` | `incept` (registry `vcp`), `issue`, `revoke`, `isTransactionEvent` |
| `keri/routed-events` | `exchange`, `query`, `reply`, `embeds`, `IPEX_GRANT_ROUTE`, `isRoutedEvent` |
| `keri/credentials` | `create`, `disclosedAttributes`, `isCredential` |

Reference implementations of a witness, a mailbox, a controller and a verifier — the parts that
need HTTP and a database — live in this repository under `packages/keri-infra` and `apps/`, and are
not published.
