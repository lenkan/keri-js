import { KERIPy } from "../test_utils/keripy.ts";

const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

export interface IssuedCredential {
  said: string;
  stream: string;
}

/**
 * Mints a credential with `kli`, following the recipe the verifier prints in its "Generate one
 * locally" section. `--toad 0` keeps it witness-free, so nothing has to be served for this to work —
 * but `kli vc create` still needs the schema, which is resolved over the network.
 */
export async function issueCredential(): Promise<IssuedCredential> {
  const kli = new KERIPy();

  await kli.init();
  await kli.incept({ toad: 0 });
  await kli.oobi.resolve(`https://weboftrust.github.io/oobi/${QVI_SCHEMA}`);
  await kli.registry.incept({ registryName: "e2e-registry" });
  await kli.vc.create({
    registryName: "e2e-registry",
    schema: QVI_SCHEMA,
    recipient: await kli.aid(),
    data: { LEI: "1234567890123456789" },
  });

  const saids = (await kli.vc.list({ said: true, issued: true })).split("\n").filter((line) => line.trim().length > 0);
  const said = saids.at(-1);
  if (!said) {
    throw new Error("kli vc list reported no issued credential");
  }

  return { said: said.trim(), stream: await kli.vc.export({ said: said.trim() }) };
}
