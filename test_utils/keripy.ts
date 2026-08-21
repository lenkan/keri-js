import type { Buffer } from "node:buffer";
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import debug, { type Debugger } from "debug";

const KLI = join(dirname(fileURLToPath(import.meta.url)), "..", ".venv/bin/kli");
const TIMEOUT = 20000;
const TAIL = 2000;

// KERIpy creates the shared config directory with an unguarded exists-then-makedirs (hio
// `Filer.remake`), so two `kli` processes starting at once can both try to create it and the loser
// dies with "[Errno 17] File exists". A recursive mkdir from here is idempotent between callers.
function ensureConfigDir(base?: string): void {
  try {
    mkdirSync(join(homedir(), ".keri", "cf", base ?? ""), { recursive: true });
  } catch {
    // Whatever KERIpy does next will report it better than we can.
  }
}

function format(args: string[]): string {
  return `kli ${args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg)).join(" ")}`;
}

export class KERIPy {
  readonly name: string;
  readonly base: string | undefined;
  readonly passcode: string | undefined;
  private readonly debug: Debugger;

  constructor(opts: { base?: string; passcode?: string } = {}) {
    if (!existsSync(KLI)) {
      throw new Error(`kli not found at ${KLI}, make sure to set up the .venv and install keripy`);
    }

    this.name = `test_${randomBytes(4).toString("hex")}`;
    this.base = opts.base;
    // keripy 1.3.6's `kli witness start` refuses non-interactive startup for
    // keystores without a passcode (its aeid guard checks `is None` while
    // --nopasscode stores ''), so witness keystores get one.
    this.passcode = opts.passcode;
    this.debug = debug(`keripy:${this.name}`);

    ensureConfigDir(this.base);
  }

  private get baseArgs(): string[] {
    return [...(this.base ? ["--base", this.base] : []), ...(this.passcode ? ["--passcode", this.passcode] : [])];
  }

  private log(message: string): void {
    for (const line of message.split("\n").filter(Boolean)) {
      this.debug(line);
    }
  }

  private run(args: string[], timeout = TIMEOUT): Promise<string> {
    const command = format(args);
    this.log(command);
    return new Promise((resolve, reject) => {
      const child = spawn(KLI, args, { timeout });
      // `output` is what callers parse, so it stays stdout-only; `tail` is both streams, for the
      // error message. `kli` reports a failed resolve on stdout and the traceback on stderr.
      let output = "";
      let tail = "";
      const append = (chunk: Buffer) => {
        tail = (tail + chunk.toString()).slice(-TAIL);
      };

      child.stdout.on("data", (d: Buffer) => {
        const message = d.toString();
        this.log(message);
        output += message;
        append(d);
      });
      child.stderr.on("data", (d: Buffer) => {
        this.log(d.toString());
        append(d);
      });
      child.on("error", (err) => {
        reject(err);
      });
      // `close` rather than `exit`, so the tail has everything the process wrote before it died.
      child.on("close", (code, signal) => {
        if (code === 0) {
          resolve(output.trim());
          return;
        }

        const reason = code === null ? `killed (${signal}) after ${TIMEOUT}ms` : `exited (code=${code})`;
        reject(new Error(`${command} ${reason}: ${tail.trim().replaceAll("\n", " ") || "<no output>"}`));
      });
    });
  }

  cleanup(): void {
    // Not implemented
  }

  async init(opts: { salt?: string } = {}): Promise<void> {
    // baseArgs already carries --passcode when one is configured.
    const args = ["init", "--name", this.name, ...this.baseArgs, ...(this.passcode ? [] : ["--nopasscode"])];
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
    opts: {
      alias?: string;
      wits?: string[];
      toad?: number;
      receiptEndpoint?: boolean;
      transferable?: boolean;
      delpre?: string;
      proxy?: string;
    } = {},
  ): Promise<void> {
    const args: string[] = [
      "incept",
      "--name",
      this.name,
      "--alias",
      opts.alias ?? this.name,
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
    if (opts.delpre) {
      args.push("--delpre", opts.delpre);
    }
    if (opts.proxy) {
      args.push("--proxy", opts.proxy);
    }
    await this.run(args);
  }

  async aid(opts: { alias?: string } = {}): Promise<string> {
    return this.run(["aid", "--name", this.name, "--alias", opts.alias ?? this.name, ...this.baseArgs]);
  }

  async export(opts: { alias?: string } = {}): Promise<string> {
    return this.run(["export", "--name", this.name, "--alias", opts.alias ?? this.name, ...this.baseArgs]);
  }

  async rotate(opts: { alias?: string } = {}): Promise<void> {
    await this.run(["rotate", "--name", this.name, "--alias", opts.alias ?? this.name, ...this.baseArgs]);
  }

  ends = {
    add: async (opts: { alias?: string; eid: string; role?: string }): Promise<void> => {
      await this.run([
        "ends",
        "add",
        "--name",
        this.name,
        "--alias",
        opts.alias ?? this.name,
        ...this.baseArgs,
        "--role",
        opts.role ?? "mailbox",
        "--eid",
        opts.eid,
      ]);
    },
  };

  mailbox = {
    /** `mailbox` is a contact alias or AID; the mailbox must be resolved as a contact first. */
    add: async (opts: { alias?: string; mailbox: string }): Promise<void> => {
      await this.run([
        "mailbox",
        "add",
        "--name",
        this.name,
        "--alias",
        opts.alias ?? this.name,
        ...this.baseArgs,
        "--mailbox",
        opts.mailbox,
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
    start: (opts: {
      http: number;
      tcp: number;
      logLevel?: string;
      signal?: AbortSignal;
    }): ChildProcessWithoutNullStreams => {
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

  delegate = {
    confirm: async (opts: { alias?: string; interact?: boolean; auto?: boolean } = {}): Promise<void> => {
      const args = ["delegate", "confirm", "--name", this.name, "--alias", opts.alias ?? this.name, ...this.baseArgs];
      if (opts.interact !== false) {
        args.push("--interact");
      }
      if (opts.auto !== false) {
        args.push("--auto");
      }
      await this.run(args);
    },
  };

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
    /** `recipient` is a contact alias, so resolve the recipient's OOBI with that alias first. */
    respond: async (opts: { alias?: string; words: string[]; recipient: string }): Promise<void> => {
      await this.run([
        "challenge",
        "respond",
        "--name",
        this.name,
        "--alias",
        opts.alias ?? this.name,
        ...this.baseArgs,
        "--words",
        opts.words.join(" "),
        "--recipient",
        opts.recipient,
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
        // Longer than the default: admit polls its mailbox for the TEL replay
        // before it can verify and respond.
        await this.run(
          ["ipex", "admit", "--name", this.name, "--alias", this.name, ...this.baseArgs, "--said", said],
          60000,
        );
      } catch {
        // kli ipex admit may exit non-zero but still succeed
      }
    },
    grant: async (opts: { said: string; recipient: string; message?: string }): Promise<void> => {
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
        ...(opts.message ? ["--message", opts.message] : []),
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
    /** SAIDs of the issued credentials — order is NOT chronological. */
    saids: async (): Promise<string[]> => {
      const output = await this.vc.list({ said: true, issued: true });
      return output.split("\n").filter((line) => line.trim().length > 0);
    },
    export: async (opts: { said: string }): Promise<string> => {
      return this.run([
        "vc",
        "export",
        "--name",
        this.name,
        "--alias",
        this.name,
        ...this.baseArgs,
        "--said",
        opts.said,
        "--full",
      ]);
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
