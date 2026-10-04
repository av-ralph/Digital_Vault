import { createApp } from "../server/app.js";
import { defaults } from "../server/config.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
// Isolated UI verification only. This harness never opens the application's database.
const directory = mkdtempSync(path.join(tmpdir(), "loginlab-browser-"));
const service = createApp({
  port: 3410,
  databasePath: path.join(directory, "isolated.sqlite"),
  trustedOrigins: ["http://127.0.0.1:3410"],
  trustedProxyIps: [],
  policy: { ...defaults, ipLimit: 100, accountLimit: 100 },
});
const server = service.app.listen(3410, "127.0.0.1", () =>
  console.log("Isolated browser verification: http://127.0.0.1:3410"),
);
// Only the test operator can promote an account created through this isolated registration flow.
process.stdin.on("data", (chunk) => {
  const command = String(chunk).trim();
  if (command.startsWith("admin ")) {
    const username = command.slice(6);
    if (/^[a-z0-9_.-]{3,32}$/.test(username)) {
      service.store.db
        .prepare("UPDATE users SET role='admin' WHERE username=?")
        .run(username);
      console.log(
        "Isolated account authorized for administrator browser checks.",
      );
    }
  }
});
function stop() {
  server.closeAllConnections();
  server.close(() => {
    service.close();
    const resolved = path.resolve(directory);
    if (
      resolved.startsWith(path.resolve(tmpdir()) + path.sep) &&
      path.basename(resolved).startsWith("loginlab-browser-")
    )
      rmSync(resolved, { recursive: true, force: true });
    process.exit(0);
  });
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
