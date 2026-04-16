import type { Buffer } from "node:buffer";
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import debug, { type Debugger } from "debug";

const KLI = join(dirname(fileURLToPath(import.meta.url)), "..", ".venv/bin/kli");

export class KERIPy {
  readonly name: string;
  readonly base: string | undefined;
  private readonly debug: Debugger;

  constructor(opts: { base?: string } = {}) {
    this.name = `test_${randomBytes(4).toString("hex")}`;
    this.base = opts.base;
    this.debug = debug(`keripy:${this.name}`);
  }

  private get baseArgs(): string[] {
    return this.base ? ["--base", this.base] : [];
  }

  private log(message: string): void {
    for (const line of message.split("\n").filter(Boolean)) {
      this.debug(line);
    }
  }

  private run(args: string[]): Promise<string> {
    this.log(`kli ${args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg)).join(" ")}`);
    return new Promise((resolve, reject) => {
      const child = spawn(KLI, args, { timeout: 20000 });
      let output = "";
      child.stdout.on("data", (d: Buffer) => {
        const message = d.toString();
        this.log(message);
        output += message;
      });
      child.stderr.on("data", (d: Buffer) => this.log(d.toString()));
      child.on("error", (err) => {
        reject(err);
      });
      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error(`kli ${args[0]} failed`));
        } else {
          resolve(output.trim());
        }
      });
    });
  }

  cleanup(): void {
    // Not implemented
  }

  async init(opts: { salt?: string } = {}): Promise<void> {
    const args = ["init", "--name", this.name, ...this.baseArgs, "--nopasscode"];
    if (opts.salt) {
      args.push("--salt", opts.salt);
    }
    await this.run(args);
  }

  oobi = {
    resolve: async (oobi: string, alias?: string): Promise<void> => {
      const args = ["oobi", "resolve", "--name", this.name, ...this.baseArgs];
      if (alias) {
        args.push("--oobi-alias", alias);
      }
      args.push("--oobi", oobi);
      await this.run(args);
    },
  };

  async status(): Promise<void> {
    await this.run(["status", "--name", this.name, ...this.baseArgs]);
  }

  async incept(
    opts: { wits?: string[]; toad?: number; receiptEndpoint?: boolean; transferable?: boolean } = {},
  ): Promise<void> {
    const args: string[] = [
      "incept",
      "--name",
      this.name,
      "--alias",
      this.name,
      ...this.baseArgs,
      "--icount",
      "1",
      "--isith",
      "1",
      "--ncount",
      "1",
      "--nsith",
      "1",
    ];

    if (opts.transferable !== false) {
      args.push("--transferable");
    }

    if (opts.toad !== undefined) {
      args.push("--toad", String(opts.toad));
    }
    for (const wit of opts.wits ?? []) {
      args.push("--wits", wit);
    }
    if (opts.receiptEndpoint) {
      args.push("--receipt-endpoint");
    }
    await this.run(args);
  }

  async aid(): Promise<string> {
    return this.run(["aid", "--name", this.name, "--alias", this.name, ...this.baseArgs]);
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
        ...this.baseArgs,
        "--role",
        opts.role ?? "mailbox",
        "--eid",
        opts.eid,
      ]);
    },
  };

  location = {
    add: async (opts: { url: string }): Promise<void> => {
      await this.run([
        "location",
        "add",
        "--name",
        this.name,
        "--alias",
        this.name,
        ...this.baseArgs,
        "--url",
        opts.url,
      ]);
    },
  };

  witness = {
    start: (opts: { http: number; tcp: number; logLevel?: string; signal?: AbortSignal }): ChildProcess => {
      const args = [
        "witness",
        "start",
        "--name",
        this.name,
        "--alias",
        this.name,
        ...this.baseArgs,
        "--loglevel",
        opts.logLevel ?? "CRITICAL",
        "-H",
        String(opts.http),
        "-T",
        String(opts.tcp),
      ];
      const command = `kli ${args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg)).join(" ")}`;
      this.log(command);
      const child = spawn(KLI, args, { signal: opts.signal });
      child.on("error", (error: Error) => {
        this.log(`failed to start ${command}: ${error.message}`);
      });
      child.on("exit", (code, signal) => {
        this.log(`witness process exited with code=${code ?? "null"} signal=${signal ?? "null"}`);
      });
      child.stdout.on("data", (d: Buffer) => {
        for (const line of d.toString().split("\n").filter(Boolean)) {
          this.log(line);
        }
      });
      child.stderr.on("data", (d: Buffer) => {
        for (const line of d.toString().split("\n").filter(Boolean)) {
          this.log(line);
        }
      });
      return child;
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
        ...this.baseArgs,
        "--registry-name",
        opts.registryName,
      ]);
    },
  };

  async query(opts: { prefix: string }): Promise<void> {
    await this.run(["query", "--name", this.name, "--alias", this.name, ...this.baseArgs, "--prefix", opts.prefix]);
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
        ...this.baseArgs,
        "--words",
        opts.words.join(" "),
        "--signer",
        opts.signer,
      ]);
    },
  };

  ipex = {
    list: async (opts: { type?: string; poll?: boolean; said?: boolean } = {}): Promise<string[]> => {
      const args = ["ipex", "list", "--name", this.name, ...this.baseArgs];
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
        await this.run(["ipex", "admit", "--name", this.name, "--alias", this.name, ...this.baseArgs, "--said", said]);
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
        ...this.baseArgs,
        "--said",
        opts.said,
        "--recipient",
        opts.recipient,
      ]);
    },
  };

  vc = {
    list: async (opts: { said?: boolean; issued?: boolean } = {}): Promise<string> => {
      const args = ["vc", "list", "--name", this.name, "--alias", this.name, ...this.baseArgs];
      if (opts.said) {
        args.push("--said");
      }
      if (opts.issued) {
        args.push("--issued");
      }
      return this.run(args);
    },
    create: async (opts: {
      registryName: string;
      schema: string;
      recipient: string;
      data: Record<string, unknown>;
    }): Promise<void> => {
      await this.run([
        "vc",
        "create",
        "--name",
        this.name,
        "--alias",
        this.name,
        ...this.baseArgs,
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
