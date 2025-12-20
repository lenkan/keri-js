import * as readline from "node:readline";
import * as process from "node:process";

export async function pinentry(prompt: string): Promise<string | null> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
    });

    let input = "";

    process.stdout.write(prompt + " ");

    readline.emitKeypressEvents(process.stdin);
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }

    const cleanup = () => {
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      process.stdin.removeListener("keypress", handleKeyPress);
      rl.close();
      process.stdout.write("\n");
    };

    const handleKeyPress = (str: string, key: readline.Key) => {
      if (key.name === "return") {
        cleanup();
        resolve(input);
      } else if (key.name === "escape" || (key.ctrl && key.name === "c")) {
        cleanup();
        resolve(null);
      } else if (key.name === "backspace") {
        if (input.length > 0) {
          input = input.slice(0, -1);
          process.stdout.write("\x1B[1D \x1B[1D");
        }
      } else if (str && !key.ctrl && !key.meta) {
        input += str;
        process.stdout.write("*");
      }
    };

    process.stdin.on("keypress", handleKeyPress);
  });
}
