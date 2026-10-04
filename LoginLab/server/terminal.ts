import { stdin, stdout } from "node:process";
export function secret(prompt: string): Promise<string> {
  if (!stdin.isTTY)
    throw new Error(
      "Administrator setup requires an interactive terminal so passwords are not exposed in command arguments.",
    );
  stdout.write(prompt);
  stdin.setRawMode(true);
  stdin.resume();
  return new Promise((resolve, reject) => {
    let value = "";
    const handler = (chunk: Buffer) => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\u0003") {
          finish();
          reject(new Error("Setup cancelled."));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          resolve(value);
          return;
        }
        if (character === "\u007f" || character === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        if (character >= " " && value.length < 129) value += character;
      }
    };
    function finish() {
      stdin.off("data", handler);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write("\n");
    }
    stdin.on("data", handler);
  });
}
