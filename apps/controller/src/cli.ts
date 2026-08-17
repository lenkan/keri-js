/** biome-ignore-all lint/suspicious/noConsole: CLI */
import type { Controller } from "@keri-js/infra/controller";
import { encodeText, type Message, parse } from "cesr";

export interface CommandLineInterface {
  args: string[];
  read(input: string): AsyncIterableIterator<Uint8Array>;
  controller(): Promise<Controller>;
}

interface Arguments {
  options: Record<string, string | boolean>;
  _: string[];
}

const HELP = [
  "Usage: keri <command> [options]",
  "",
  "Commands:",
  "  incept                     Create a new identifier",
  "  rotate <id>                Rotate the keys of an identifier",
  "  oobi resolve <url>         Resolve an OOBI and store the resulting key state",
  "  query <id> <topic>         Query the identifier's mailbox for a topic",
  "  export <id>                Write the identifier's key event log to stdout",
  "  parse <input>              Parse a CESR stream. Use '-' for stdin, or pass a URL or file",
  "",
  "Options:",
  "  --wits=<aid,aid>           Witness identifiers for incept",
  "  --toad=<n>                 Witness threshold for incept",
  "  --pretty                   Pretty print the output",
  "  --help                     Show help",
].join("\n");

function parseArgs(inputArgs: string[]): Arguments {
  const args: string[] = [];
  const options: Record<string, string | boolean> = {};

  for (const arg of inputArgs) {
    if (!arg.startsWith("--")) {
      args.push(arg);
      continue;
    }

    if (arg.includes("=")) {
      const [key, value] = arg.split("=");
      options[key] = value;
      continue;
    }

    options[arg] = true;
  }

  return { _: args, options };
}

function fail(message: string): never {
  throw new Error(`${message}\n\n${HELP}`);
}

function required(args: Arguments, index: number, name: string): string {
  const value = args._[index];
  if (typeof value !== "string" || value.length === 0) {
    fail(`Missing <${name}>.`);
  }
  return value;
}

function list(value: string | boolean | undefined): string[] {
  return typeof value === "string" ? value.split(",").filter((entry) => entry.length > 0) : [];
}

function emit(value: unknown, pretty: boolean): void {
  if (pretty) {
    console.dir(value, { depth: 100, colors: true });
  } else {
    console.log(JSON.stringify(value));
  }
}

async function print(messages: AsyncIterable<Message> | Iterable<Message>, pretty: boolean): Promise<void> {
  for await (const message of messages) {
    emit({ payload: message.body, attachments: message.attachments.frames().map(encodeText) }, pretty);
  }
}

export async function execute(cli: CommandLineInterface): Promise<void> {
  const app = parseArgs(cli.args);
  const pretty = app.options["--pretty"] === true;
  const command = app._[0];

  if (app.options["--help"] || command === undefined) {
    console.log(HELP);
    return;
  }

  switch (command) {
    case "incept": {
      const controller = await cli.controller();
      const toad = app.options["--toad"];
      const { id, event } = await controller.incept({
        wits: list(app.options["--wits"]),
        toad: typeof toad === "string" ? parseInt(toad, 10) : undefined,
      });
      emit({ id, event }, pretty);
      return;
    }
    case "rotate": {
      const controller = await cli.controller();
      const { id, event } = await controller.rotate(required(app, 1, "id"), {});
      emit({ id, event }, pretty);
      return;
    }
    case "oobi": {
      if (app._[1] !== "resolve") {
        fail(`Unknown oobi subcommand: ${app._[1] ?? ""}`);
      }
      const controller = await cli.controller();
      const state = await controller.introduce(required(app, 2, "url"));
      emit(state, pretty);
      return;
    }
    case "query": {
      const controller = await cli.controller();
      await print(await controller.query(required(app, 1, "id"), required(app, 2, "topic")), pretty);
      return;
    }
    case "export": {
      const controller = await cli.controller();
      await print(await controller.export(required(app, 1, "id")), pretty);
      return;
    }
    case "parse": {
      await print(parse(cli.read(required(app, 1, "input"))), pretty);
      return;
    }
    default:
      fail(`Unknown command: ${command}`);
  }
}
