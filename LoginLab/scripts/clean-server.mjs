import { rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const target = path.resolve(root, "dist-server");
if (path.dirname(target) !== root || path.basename(target) !== "dist-server")
  throw new Error("Refusing to remove build output outside the project.");
rmSync(target, { recursive: true, force: true });
