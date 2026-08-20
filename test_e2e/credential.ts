import { KERIPy } from "../test_utils/keripy.ts";

export const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
export const REGISTRY_NAME = "e2e-registry";

export interface IssuedCredential {
  said: string;
  stream: string;
  /** Kept so a test can go on to present the credential from the same keystore. */
  kli: KERIPy;
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
  await kli.registry.incept({ registryName: REGISTRY_NAME });
  await kli.vc.create({
    registryName: REGISTRY_NAME,
    schema: QVI_SCHEMA,
    recipient: await kli.aid(),
    data: { LEI: "1234567890123456789" },
  });

  const said = (await kli.vc.saids()).at(-1);
  if (!said) {
    throw new Error("kli vc list reported no issued credential");
  }

  return { said: said.trim(), stream: await kli.vc.export({ said: said.trim() }), kli };
}
