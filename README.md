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
`RoutedEvent` (`exn`/`qry`/`rpy`) and `Credential` (ACDC). Both `KeyEvent.incept` and
`TransactionEvent.incept` are called `incept` — one is a KEL inception, the other a registry's — so
the grouping is what tells them apart.

Namespaces are nouns; the top level is verbs and the state they act on, so a pipeline reads without
a prefix:

```ts
import { generateKeyPair, KeyEvent, KeyEventLog, signEvent } from "keri";

const key = generateKeyPair();
const next = generateKeyPair();

const log = KeyEventLog.empty().append(
  signEvent(KeyEvent.incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] }), {
    signers: [key],
  }),
);
```

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

`signingThreshold` and `nextThreshold` accept a count as a hex string — ten is `"a"` — or a list of
fractional weights such as `["1/2", "1/2", "1/2"]`. Both default to every key being required, where
KERIpy defaults to a majority, so pass them explicitly to build the same event from the same key
list. `backerThreshold` defaults to the KERI fault-tolerant threshold for the number of backers:
three backers require all three.

`configTraits` writes the `c` field, from KERI's trait codes: `EO` (establishment events only),
`DND` (do not delegate). They are recorded in `KeyState.configTraits`; nothing enforces them.

A key that must be awaited — an HSM, a hardware wallet, a non-extractable WebCrypto `CryptoKey` —
is not a `Signer`, because `Signer.sign` is synchronous. Sign with it yourself and pass the result
as `signatures: [{ publicKey, signature }]` instead.

### Delegated identifiers

A delegated event only counts once the delegator has anchored it: an event in the delegator's KEL
whose `a` carries a seal naming the delegated event, and a `SealSourceCouple` on the delegated event
naming that anchoring event back.

```ts
import { KeyEvent, KeyEventLog, signEvent } from "keri";

const dip = KeyEvent.delegatedIncept({
  signingKeys: [delegate.publicKey],
  nextKeyDigests: [delegateNext.publicKeyDigest],
  delegator: delegator.state.identifier,
});

const anchor = KeyEvent.interact(delegator.state, { data: KeyEvent.keyEventSeal(dip) });
signEvent(anchor, { signers: [delegatorKey], state: delegator.state });
const anchored = delegator.append(anchor);

signEvent(dip, { signers: [delegate] });
KeyEvent.attachSourceSeal(dip, anchor);

const log = KeyEventLog.empty().append(dip, { delegator: anchored });
```

`append` verifies the anchor only when passed a `delegator` KEL; without one it takes the event on
its signatures alone. `KeyEventLog.parse` builds the chain itself when the stream carries both
identifiers, which is what an OOBI response for a delegated AID returns.

A `drt` carries no `di` — v1 gives it the same fields as `rot` — so the delegator it is held to is
the one its `dip` established.

### Witness receipts

A backer receipts an event by signing the event and returning an `rct`. The controller folds those
receipts back onto the event, which is the form an exported KEL travels in.

```ts
import { KeyEvent, KeyEventLog, signEvent } from "keri";

const icp = KeyEvent.incept({
  signingKeys: [current.publicKey],
  nextKeyDigests: [next.publicKeyDigest],
  backers: [witness.publicKey],
});

signEvent(icp, { signers: [current] });

const backers = KeyEvent.backersFor(icp, null);
const rct = KeyEvent.receipt(icp, { signers: [witness], backers });
KeyEvent.applyReceipt(icp, rct, backers);

const log = KeyEventLog.empty().append(icp);
```

`receipt` signs the event, not the receipt — a signature over the `rct` itself would verify against
nothing. Passing `backers` is what makes it a witness receipt, indexed by position in that set;
leave it out and the signature travels as a bare couple naming its own key, which `applyReceipt`
promotes back to an indexed one. A couple from outside the backer set is dropped: a key event has
nowhere to carry it.

`backersFor` gives the set that has to receipt an event — `null` for an inception, which carries its
backers itself, and the key state for anything after one. A rotation is receipted by the set it
establishes, not the one it replaces.

`append` requires the backer threshold to be met. Pass `allowPartiallyWitnessed` for an event still
collecting receipts.

`rct` is not a key event: `append` rejects it and `KeyEventLog.parse` ignores it. Apply a receipt to
the event it names before storing the event.

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

Base64url and UTF-8 helpers come from the same place:

```ts
import { decodeBase64Url, encodeBase64Url } from "keri/cesr";
```

## Protocol versions

Constructors emit KERI v1. Reading is version-tolerant: `parse`, `collect` and `verify` accept any
version string a message carries, and SAIDs are recomputed against the version the body declares —
minor version and serialization kind included.

Writing v2 is not supported yet. It needs CESR attachment groups to be emitted with v2 counter
codes, which the encoder does not do.

## Entry points

Two, and only two.

| Import | Contents |
| --- | --- |
| `keri` | the four namespaces, `KeyEventLog`, signing and endorsement, keys, verification, `Message` |
| `keri/cesr` | the byte layer: `Matter`, `Indexer`, `Counter`, `Attachments`, `parse`, `VersionString`, base64url and UTF-8 |

`Message` is the one name in both, because every constructor returns one.

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

`src/cesr/codes.ts` is generated from KERIpy's code tables, `fixtures/cesr_test_vectors.json` from
its primitives, and `fixtures/events/` from its event constructors. All need a `.venv` with KERIpy
from `requirements.txt`:

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/generate-codec.py > src/cesr/codes.ts
.venv/bin/python scripts/generate-test-vector.py > fixtures/cesr_test_vectors.json
.venv/bin/python scripts/generate-event-vectors.py fixtures/events
```

That last one writes `fixtures/events/keri-<version>/`, one file per key event log. It owns that
directory and clears the `.json` in it first, so a renamed log leaves nothing stale behind. The test
reads whatever directories are there, so a second KERIpy version is a directory to drop in.

One file, one key event log:

```jsonc
{
  "keripy": "1.3.6",
  "name": "backers",
  "version": "1.0",
  "controllers": [{ "seed": "<hex>", "public": "DGx7..." }, ...],
  "backers":     [{ "seed": "<hex>", "public": "BKK9..." }, ...],
  "events": [
    {
      "name": "icp",           // what the event is there to show, where `t` and `s` are not enough
      "sad": { "v": "KERI10JSON...", "t": "icp", ... },
      "raw": "{\"v\":\"KERI10JSON...\",...}",
      "attachments": "-VBa-AAB...",
    }
  ],
  "state": { "i": "...", "kt": "1", ... }   // KERIpy's key state record, minus its first-seen `dt`
}
```

Nothing here is specific to keri-js. A message is `raw + attachments`, a log's stream is those
concatenated, and the arguments an event was built from are the fields of its own `sad`. Which keys
signed is recorded only by the indices the attached signatures carry, so a 2-of-3 signed by keys 0
and 2 says so on the wire.

A delegated log carries the delegator's events too, in stream order, the way an OOBI response
delivers them. `controllers` then covers every identifier in the file, and `state` is the delegate's
— which its own `i` names.

`backers` holds the log's non-transferable keys, which is not quite the same as the `b` field of its
events: the `receipts` log also lists a receiptor that no event designates as a backer.

A seed derives both a transferable `D…` key and a non-transferable `B…` one, so each entry names the
form its log uses. Checking that a seed derives the key beside it is a cheap first test of an
implementation's key derivation, before any of the events are read.
