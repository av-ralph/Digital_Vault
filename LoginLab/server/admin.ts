import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { configuration, registrationSchema } from "./config.js";
import { Store } from "./store.js";
import { Auth } from "./auth.js";
import { secret } from "./terminal.js";
const config = configuration();
const store = new Store(config.databasePath, config.policy);
const auth = new Auth(store);
try {
  if (process.argv.includes("--init")) {
    console.log(
      "SQLite schema initialized. No accounts or login events were added.",
    );
  } else {
    if (
      store.db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get()
    )
      throw new Error(
        "Administrator setup is already complete. Sign in as an administrator to create additional accounts.",
      );
    if (!stdin.isTTY)
      throw new Error(
        "Run npm run admin:setup in an interactive PowerShell terminal.",
      );
    const rl = createInterface({ input: stdin, output: stdout });
    const username = await rl.question("Administrator username: ");
    rl.close();
    const password = await secret(
      "Administrator password (hidden, 15–128 characters): ",
    );
    const confirmation = await secret("Confirm password (hidden): ");
    if (password !== confirmation) throw new Error("Passwords do not match.");
    const credentials = registrationSchema.safeParse({ username, password });
    if (!credentials.success)
      throw new Error(
        "Use a 3–32 character username (letters/digits/dot/underscore/hyphen) and a password of 15–128 characters.",
      );
    await auth.createUser(
      credentials.data.username,
      credentials.data.password,
      "admin",
      true,
    );
    console.log("Administrator created. Sign in through the portal.");
  }
} catch (err) {
  console.error(
    err instanceof Error &&
      /^(Administrator setup|Setup cancelled|Run npm|Passwords do|Use a )/.test(
        err.message,
      )
      ? err.message
      : "Administrator setup failed. No credentials were printed.",
  );
  process.exitCode = 1;
} finally {
  store.close();
}
