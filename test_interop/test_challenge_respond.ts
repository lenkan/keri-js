import assert from "node:assert";
import { keri } from "../src/main.ts";
import { KERIPy } from "./keripy.ts";
import { createController, resolveWitness } from "./utils.ts";

const wan = await resolveWitness("http://localhost:5642");
const wil = await resolveWitness("http://localhost:5643");

const keripy = new KERIPy();

// Set up KERIpy identity
await keripy.init();
await keripy.oobi.resolve(`http://localhost:5642/oobi`, "wan");
await keripy.oobi.resolve(`http://localhost:5643/oobi`, "wil");
await keripy.incept({ wits: [wan.aid, wil.aid], toad: 1 });
await keripy.ends.add({ eid: wan.aid });

const keripy_aid = await keripy.aid();

// Set up KeriJS identity
const controller = createController();
await controller.introduce(wan.oobi);
await controller.introduce(wil.oobi);

const jsState = await controller.incept({ wits: [wan.aid], toad: 1 });

// Cross-resolve OOBIs
const kerijs_oobi = `http://localhost:5642/oobi/${jsState.id}`;
const keripy_oobi = `http://localhost:5642/oobi/${keripy_aid}`;

await controller.introduce(keripy_oobi);
await keripy.oobi.resolve(kerijs_oobi, "kerijs");

// KERIpy generates challenge words; KeriJS sends them back
const words = await keripy.challenge.generate();
assert.equal(words.length, 12);

const exn = keri.exchange({
  sender: jsState.id,
  route: "/challenge/response",
  anchor: { i: jsState.id, words },
});

await controller.forward({
  message: exn,
  recipient: keripy_aid,
  sender: jsState.id,
  topic: "challenge",
});

// KERIpy verifies — exits 0 on success, throws on failure
await keripy.challenge.verify({ words, signer: "kerijs" });
