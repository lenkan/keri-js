/* eslint-disable no-console */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const KLI = join(dirname(fileURLToPath(import.meta.url)), "..", ".venv/bin/kli");

export class KERIPy {
  readonly name: string;

  constructor() {
    this.name = `test_${randomBytes(4).toString("hex")}`;
  }

  private run(args: string[]): Promise<string> {
    console.error(`kli ${args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg)).join(" ")}`);
    return new Promise((resolve, reject) => {
      const child = spawn(KLI, args, { timeout: 20000 });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
      child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error(`kli ${args[0]} failed:\n${stderr || stdout}`));
        } else {
          const output = stdout.trim();
          console.error(output);
          resolve(output);
        }
      });
    });
  }

  cleanup(): void {
    // Not implemented
  }

  async init(): Promise<void> {
    await this.run(["init", "--name", this.name, "--nopasscode"]);
  }

  oobi = {
    resolve: async (oobi: string, alias?: string): Promise<void> => {
      const args = ["oobi", "resolve", "--name", this.name];
      if (alias) {
        args.push("--oobi-alias", alias);
      }
      args.push("--oobi", oobi);
      await this.run(args);
    },
  };

  async incept(opts: { wits?: string[]; toad?: number; receiptEndpoint?: boolean } = {}): Promise<void> {
    const args: string[] = [
      "incept",
      "--name",
      this.name,
      "--alias",
      this.name,
      "--icount",
      "1",
      "--isith",
      "1",
      "--ncount",
      "1",
      "--nsith",
      "1",
      "--transferable",
    ];

    if (opts.receiptEndpoint) {
      args.push("--receipt-endpoint");
    }

    if (opts.toad !== undefined) {
      args.push("--toad", String(opts.toad));
    }
    for (const wit of opts.wits ?? []) {
      args.push("--wits", wit);
    }
    await this.run(args);
  }

  async aid(): Promise<string> {
    return this.run(["aid", "--name", this.name, "--alias", this.name]);
  }

  ends = {
    add: async (opts: { eid: string; role?: string }): Promise<void> => {
      await this.run([
        "ends",
        "add",
        "--name",
        this.name,
        "--alias",
        this.name,
        "--role",
        opts.role ?? "mailbox",
        "--eid",
        opts.eid,
      ]);
    },
  };

  registry = {
    incept: async (opts: { registryName: string }): Promise<void> => {
      await this.run([
        "vc",
        "registry",
        "incept",
        "--name",
        this.name,
        "--alias",
        this.name,
        "--registry-name",
        opts.registryName,
      ]);
    },
  };

  async query(opts: { prefix: string }): Promise<void> {
    await this.run(["query", "--name", this.name, "--alias", this.name, "--prefix", opts.prefix]);
  }

  challenge = {
    generate: async (): Promise<string[]> => {
      const output = await this.run(["challenge", "generate", "--out", "json"]);
      return JSON.parse(output) as string[];
    },
    verify: async (opts: { words: string[]; signer: string }): Promise<void> => {
      await this.run([
        "challenge",
        "verify",
        "--name",
        this.name,
        "--alias",
        this.name,
        "--words",
        opts.words.join(" "),
        "--signer",
        opts.signer,
      ]);
    },
  };

  ipex = {
    list: async (opts: { type?: string; poll?: boolean; said?: boolean } = {}): Promise<string[]> => {
      const args = ["ipex", "list", "--name", this.name];
      if (opts.type) {
        args.push("--type", opts.type);
      }
      if (opts.poll) {
        args.push("--poll");
      }
      if (opts.said) {
        args.push("--said");
      }
      const output = await this.run(args);
      return output.split("\n").filter((line) => line.trim().length > 0);
    },
    admit: async (said: string): Promise<void> => {
      try {
        await this.run(["ipex", "admit", "--name", this.name, "--alias", this.name, "--said", said]);
      } catch {
        // kli ipex admit may exit non-zero but still succeed
      }
    },
    grant: async (opts: { said: string; recipient: string }): Promise<void> => {
      await this.run([
        "ipex",
        "grant",
        "--name",
        this.name,
        "--alias",
        this.name,
        "--said",
        opts.said,
        "--recipient",
        opts.recipient,
      ]);
    },
  };

  vc = {
    list: async (opts: { said?: boolean; issued?: boolean } = {}): Promise<string> => {
      const args = ["vc", "list", "--name", this.name, "--alias", this.name];
      if (opts.said) {
        args.push("--said");
      }
      if (opts.issued) {
        args.push("--issued");
      }
      return this.run(args);
    },
    create: async (opts: { registryName: string; schema: string; recipient: string; data: Record<string, unknown> }): Promise<void> => {
      await this.run([
        "vc",
        "create",
        "--name",
        this.name,
        "--alias",
        this.name,
        "--registry-name",
        opts.registryName,
        "--schema",
        opts.schema,
        "--recipient",
        opts.recipient,
        "--data",
        JSON.stringify(opts.data),
      ]);
    },
  };
}
