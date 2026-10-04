import pg from "pg";
import { DatabaseSync } from "node:sqlite";
import { configuration, usernameSchema } from "./config.js";

const flag = process.argv.indexOf("--username");
const username = usernameSchema.safeParse(
  flag >= 0 ? process.argv[flag + 1] : undefined,
);
if (!process.env.NETLIFY_DB_URL || !username.success) {
  console.error(
    "Set NETLIFY_DB_URL privately and provide --username for the existing administrator to transfer.",
  );
  process.exitCode = 1;
} else {
  const source = new DatabaseSync(configuration().databasePath, {
    readOnly: true,
  });
  const pool = new pg.Pool({
    connectionString: process.env.NETLIFY_DB_URL,
    max: 1,
    connectionTimeoutMillis: 10000,
  });
  try {
    const account = source
      .prepare(
        "SELECT id,username,salt,password_hash,role,created_at FROM users WHERE username=? AND role='admin'",
      )
      .get(username.data);
    if (!account)
      throw new Error("The selected local administrator was not found.");
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
        "initial-admin",
      ]);
      if (
        (await db.query("SELECT id FROM users WHERE role='admin' LIMIT 1")).rows
          .length
      )
        throw new Error("Hosted administrator setup is already complete.");
      await db.query(
        "INSERT INTO users(id,username,salt,password_hash,role,created_at) VALUES($1,$2,$3,$4,$5,$6)",
        [
          account.id,
          account.username,
          account.salt,
          account.password_hash,
          account.role,
          account.created_at,
        ],
      );
      await db.query("COMMIT");
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    } finally {
      db.release();
    }
    console.log(
      "Existing administrator transferred privately. No passwords, sessions, or audit history were exported.",
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    console.error(
      /^(The selected local|Hosted administrator setup)/.test(message)
        ? message
        : "Administrator transfer failed. No credentials were printed.",
    );
    process.exitCode = 1;
  } finally {
    source.close();
    await pool.end();
  }
}
