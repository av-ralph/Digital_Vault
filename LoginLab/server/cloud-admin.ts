import pg from "pg";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { CloudPortal } from "./cloud.js";
import { registrationSchema } from "./config.js";
import { secret } from "./terminal.js";

const connectionString = process.env.NETLIFY_DB_URL;
if (!connectionString) {
  console.error(
    "Set NETLIFY_DB_URL privately in your environment before remote administrator setup. Never put it in Git.",
  );
  process.exitCode = 1;
} else {
  const pool = new pg.Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10000,
  });
  try {
    if (!stdin.isTTY)
      throw new Error(
        "Run this command in an interactive PowerShell terminal.",
      );
    if (
      (await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1")).rows
        .length
    )
      throw new Error("Administrator setup is already complete.");
    const rl = createInterface({ input: stdin, output: stdout });
    const username = await rl.question("Hosted administrator username: ");
    rl.close();
    const password = await secret("Hosted administrator password (hidden): ");
    const confirmation = await secret("Confirm password (hidden): ");
    if (password !== confirmation) throw new Error("Passwords do not match.");
    const data = registrationSchema.safeParse({ username, password });
    if (!data.success)
      throw new Error(
        "Use a valid username and a password of 15–128 characters.",
      );
    await new CloudPortal(pool, ["https://localhost"], "").createUser(
      data.data.username,
      data.data.password,
      "admin",
      true,
    );
    console.log(
      "Hosted administrator created. Sign in through your deployed portal.",
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    console.error(
      /^(Run this|Administrator setup|Passwords do|Use a valid|Setup cancelled)/.test(
        message,
      )
        ? message
        : "Hosted setup failed. No credentials were printed.",
    );
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}
