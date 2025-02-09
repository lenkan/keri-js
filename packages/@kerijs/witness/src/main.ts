import { ed25519 } from "@noble/curves/ed25519";
import { DynamoEventStore } from "@kerijs/db-dynamo";
import express from "express";
import { cesr, FileSystemKeyStore, Habitat, incept, MatterCode, serializeAttachment } from "keri";
import { randomUUID } from "crypto";

const db = new DynamoEventStore({
  tableName: `test_${randomUUID()}`,
  region: "eu-north-1",
  endpoint: "http://localhost:8000",
  credentials: {
    accessKeyId: "admin",
    secretAccessKey: "password",
  },
});

const keystore = new FileSystemKeyStore({
  dir: ".keri",
  passphrase: "witness",
});

const habitat = new Habitat({
  db,
  keystore,
});

await db.init();

const privateKey = Uint8Array.from(
  Buffer.from("3c794df9d5e8546f1b800c8f7b27075313422859da43c923e4423e8b634c7c00", "hex"),
);

const publicKey = ed25519.getPublicKey(privateKey);

const inception = incept({
  k: [cesr.encode(MatterCode.Ed25519N, publicKey)],
  kt: "1",
  n: [],
  nt: "0",
});

const raw = new TextEncoder().encode(JSON.stringify(inception));
const signature = cesr.sign(raw, privateKey, "ed25519");
await habitat.create(inception, [signature]);

const app = express();

app.get("/oobi", async (req, res, next) => {
  try {
    const events = await db.list({ i: inception.i });

    if (events.length === 0) {
      res.status(404);
      res.send("Not found");
      return;
    }

    res.type("application/json+cesr");
    res.status(200);

    for (const event of events) {
      res.write([JSON.stringify(event.event), serializeAttachment(event.attachments)].join(""));
    }

    res.end();
  } catch (error) {
    next(error);
  }
});

app.get("/oobi/:aid", async (req, res, next) => {
  try {
    const [event] = await db.list({ i: req.params.aid });

    if (!event) {
      res.status(404);
      res.send("Not found");
      return;
    }

    res.type("application/json+cesr");
    res.status(200);
    res.send([JSON.stringify(event), serializeAttachment(event.attachments)].join(""));
  } catch (error) {
    next(error);
  }
});

const server = app.listen(3001, () => {
  console.log(`Listening on http://localhost:3001`);
});

function shutdown() {
  server.close();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
