import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";
import type { Policy } from "./config.js";
export class Store {
  readonly db: DatabaseSync;
  constructor(filename: string, initial: Policy) {
    if (filename !== ":memory:")
      mkdirSync(path.dirname(filename), { recursive: true });
    this.db = new DatabaseSync(filename);
    this.db
      .exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE COLLATE NOCASE NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('user','admin')),created_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS csrf(token_hash TEXT PRIMARY KEY,session_hash TEXT REFERENCES sessions(token_hash) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS guards(account_key TEXT PRIMARY KEY,failures INTEGER NOT NULL DEFAULT 0,locked_until INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS rate_hits(id INTEGER PRIMARY KEY,bucket TEXT NOT NULL,at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS rate_bucket_at ON rate_hits(bucket,at);
 CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,sequence INTEGER UNIQUE NOT NULL,timestamp INTEGER NOT NULL,username TEXT NOT NULL,account_id TEXT,ip TEXT NOT NULL,user_agent TEXT NOT NULL,outcome TEXT NOT NULL,status INTEGER NOT NULL,duration_ms REAL NOT NULL,controls TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS audit_time ON audit(timestamp); CREATE INDEX IF NOT EXISTS audit_outcome ON audit(outcome);
 CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),policy TEXT NOT NULL);
 PRAGMA user_version=1;`);
    this.db
      .prepare("INSERT OR IGNORE INTO settings(id,policy) VALUES(1,?)")
      .run(JSON.stringify(initial));
  }
  policy() {
    return JSON.parse(
      (
        this.db.prepare("SELECT policy FROM settings WHERE id=1").get() as {
          policy: string;
        }
      ).policy,
    ) as Policy;
  }
  setPolicy(policy: Policy) {
    this.db
      .prepare("UPDATE settings SET policy=? WHERE id=1")
      .run(JSON.stringify(policy));
    this.pruneAudit(policy.retentionLimit);
  }
  pruneAudit(limit: number) {
    this.db
      .prepare(
        "DELETE FROM audit WHERE sequence NOT IN (SELECT sequence FROM audit ORDER BY sequence DESC LIMIT ?)",
      )
      .run(limit);
  }
  prune(now: number) {
    this.db.prepare("DELETE FROM sessions WHERE expires_at<=?").run(now);
    this.db.prepare("DELETE FROM csrf WHERE expires_at<=?").run(now);
    this.db.prepare("DELETE FROM rate_hits WHERE at<=?").run(now - 3600000);
    this.db
      .prepare("DELETE FROM guards WHERE updated_at<? AND locked_until<=?")
      .run(now - 86400000, now);
  }
  close() {
    this.db.close();
  }
}
