# keri

KERI (Key Event Receipt Infrastructure) for JavaScript. Creates key events, messages and
credentials, verifies key event logs and ACDC credentials, and encodes, decodes and parses CESR
streams.

The package is platform, transport and storage agnostic: it operates on messages and byte streams
and performs no I/O. Bring your own network and database.

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
import { generateKeyPair, KeyEvent, signEvent } from "keri";

const current = generateKeyPair();
const next = generateKeyPair();

const icp = KeyEvent.incept({
  signingKeys: [current.publicKey],
  nextKeyDigests: [next.publicKeyDigest],
});

signEvent(icp, { signers: [current] });
```

`generateKeyPair()` returns a `Signer`, so it can be passed to `signEvent` as it is. Use
`ed25519Signer(privateKey)` for a key you already hold.

`nextKeyDigests` takes digests of the next keys, not the keys themselves. Use
`nextKeyDigest(publicKey)` when rotating with a key you already hold.

A key that must be awaited — an HSM, a hardware wallet, a non-extractable WebCrypto `CryptoKey` —
is not a `Signer`, because `Signer.sign` is synchronous. Sign with it yourself and pass the result
as `signatures: [{ publicKey, signature }]` instead.

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

### CESR primitives and streams

```ts
import { encodeText, Matter, parse } from "keri/cesr";

for await (const message of parse(stream)) {
  console.log(message.body.t, message.attachments.ControllerIdxSigs);
}

const digest = Matter.crypto.blake3_256(bytes);
const qb64 = encodeText(digest);
```

Base64url and UTF-8 helpers are available from a subpath:

```ts
import { decodeBase64Url, encodeBase64Url } from "keri/encoding";
```

## Protocol versions

Constructors emit KERI v1. Reading is version-tolerant: `parse`, `collect` and `verify` accept any
version string a message carries, and SAIDs are recomputed against the version the body declares —
minor version and serialization kind included.

Writing v2 is not supported yet. It needs CESR attachment groups to be emitted with v2 counter
codes, which the encoder does not do.

## Entry points

| Import | Contents |
| --- | --- |
| `keri` | everything: the four namespaces, key event logs, verification, signing, and the CESR types |
| `keri/cesr` | CESR encoding, decoding and stream parsing: `Matter`, `Indexer`, `Counter`, `Attachments`, `parse` |
| `keri/encoding` | Base64url and UTF-8 helpers |
| `keri/key-events` | `incept`, `interact`, `rotate`, `delegatedIncept`, `delegatedRotate`, `receipt`, `isKeyEvent` |
| `keri/transaction-events` | `incept` (registry `vcp`), `issue`, `revoke`, `isTransactionEvent` |
| `keri/routed-events` | `exchange`, `query`, `reply`, `embeds`, `IPEX_GRANT_ROUTE`, `isRoutedEvent` |
| `keri/credentials` | `create`, `disclosedAttributes`, `isCredential` |

## Development

```sh
npm install
npm run test            # Unit tests, straight off src
npm run lint            # Biome lint + import boundary check
npm run check           # TypeScript type-check
npm run build           # Emit dist

npm run test:vector     # Cross-impl CESR test vectors
npm run test:consumer   # Public surface, through the package name
npm run test:deno       # The same suite on Deno, straight off src
```

`test:deno` runs with `--allow-read` and nothing else. The only reads are fixture files; if a
change makes the library touch the network, the environment or the filesystem, that job fails.

`src/cesr/codes.ts` is generated from KERIpy's code tables, and `fixtures/cesr_test_vectors.json`
from its primitives. Both need a `.venv` with KERIpy from `requirements.txt`:

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/generate-codec.py > src/cesr/codes.ts
.venv/bin/python scripts/generate-test-vector.py > fixtures/cesr_test_vectors.json
```
