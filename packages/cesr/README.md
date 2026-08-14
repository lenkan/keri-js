# cesr

Composable Event Streaming Representation (CESR) for JavaScript. Encodes and decodes CESR
primitives, counters, attachment groups and message streams.

## Install

```sh
npm install cesr
```

Requires Node.js 22 or later. Runs in Deno and in the browser.

## Usage

```ts
import { encodeText, Matter, parse } from "cesr";

for await (const message of parse(stream)) {
  console.log(message.body.t, message.attachments.ControllerIdxSigs);
}

const digest = Matter.crypto.blake3_256(bytes);
const qb64 = encodeText(digest);
```

Base64url and UTF-8 helpers are available from a subpath:

```ts
import { decodeBase64Url, encodeBase64Url } from "cesr/encoding";
```
