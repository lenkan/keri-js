/* eslint-disable no-console */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const KLI = join(dirname(fileURLToPath(import.meta.url)), "../../..", ".venv/bin/kli");

export class KERIPy {
  readonly name: string;

  constructor() {
    this.name = `test_${randomBytes(4).toString("hex")}`;
  }

  private run(args: string[]): string {
    console.error(`kli ${args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg)).join(" ")}`);
    const result = spawnSync(KLI, [...args], { encoding: "utf8", timeout: 20000 });
    if (result.status !== 0) {
      throw new Error(`kli ${args[0]} failed:\n${result.stderr}`);
    }
    const output = result.stdout.trim();
    console.error(output);
    return output;
  }

  cleanup(): void {
    // Not implemented
  }

  init(): void {
    const args = ["init", "--name", this.name, "--nopasscode"];
    this.run(args);
  }

  oobi = {
    resolve: (oobi: string, alias?: string) => {
      const args = ["oobi", "resolve", "--name", this.name];
      if (alias) {
        args.push("--oobi-alias", alias);
      }
      args.push("--oobi", oobi);
      this.run(args);
    },
  };

  incept(opts: { wits?: string[]; toad?: number } = {}): void {
    const args = [
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
    if (opts.toad !== undefined) {
      args.push("--toad", String(opts.toad));
    }
    for (const wit of opts.wits ?? []) {
      args.push("--wits", wit);
    }
    this.run(args);
  }

  aid(): string {
    return this.run(["aid", "--name", this.name, "--alias", this.name]);
  }

  ends = {
    add: (opts: { eid: string; role?: string }) => {
      this.run([
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
    incept: (opts: { registryName: string }) => {
      this.run([
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

  query(opts: { prefix: string }): void {
    this.run(["query", "--name", this.name, "--alias", this.name, "--prefix", opts.prefix]);
  }

  challenge = {
    generate: (): string[] => {
      const output = this.run(["challenge", "generate", "--out", "json"]);
      return JSON.parse(output) as string[];
    },
    verify: (opts: { words: string[]; signer: string }) => {
      this.run([
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
    list: (opts: { type?: string; poll?: boolean; said?: boolean } = {}): string[] => {
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
      const output = this.run(args);
      return output.split("\n").filter((line) => line.trim().length > 0);
    },
    admit: (said: string) => {
      try {
        this.run(["ipex", "admit", "--name", this.name, "--alias", this.name, "--said", said]);
      } catch {
        // kli ipex admit may exit non-zero but still succeed
      }
    },
    grant: (opts: { said: string; recipient: string }) => {
      this.run([
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
    list: (opts: { said?: boolean; issued?: boolean } = {}) => {
      const args = ["vc", "list", "--name", this.name, "--alias", this.name];
      if (opts.said) args.push("--said");
      if (opts.issued) args.push("--issued");
      return this.run(args);
    },
    create: (opts: { registryName: string; schema: string; recipient: string; data: Record<string, unknown> }) => {
      this.run([
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
