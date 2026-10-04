import {
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { Store } from "./store.js";
import { safeUsername, type Policy } from "./config.js";
export type User = {
  id: string;
  username: string;
  role: "user" | "admin";
  createdAt: number;
};
type StoredUser = {
  id: string;
  username: string;
  role: "user" | "admin";
  salt: string;
  password_hash: string;
  created_at: number;
};
export type AuditInput = {
  id: string;
  username: string;
  accountId: string | null;
  ip: string;
  userAgent: string;
  outcome: "success" | "failure" | "blocked" | "challenge";
  status: number;
  durationMs: number;
  controls: string[];
};
export { fingerprint, passwordHash } from "./password.js";
import { fingerprint, passwordHash } from "./password.js";
export class Auth {
  readonly neutralSalt = randomBytes(32).toString("hex");
  readonly neutralHash = randomBytes(64);
  onAudit = () => {};
  constructor(
    readonly store: Store,
    readonly now = () => Date.now(),
  ) {}
  token() {
    return randomBytes(32).toString("hex");
  }
  publicUser(user: StoredUser): User {
    return {
      id: user.id,
      username: user.username,
      role: user.role,
      createdAt: user.created_at,
    };
  }
  async createUser(
    username: string,
    password: string,
    role: "user" | "admin" = "user",
    initialAdmin = false,
  ) {
    const salt = randomBytes(32).toString("hex");
    const hash = (await passwordHash(password, salt)).toString("hex");
    const user: User = { id: randomUUID(), username, role, createdAt: this.now() };
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      if (
        initialAdmin &&
        this.store.db
          .prepare("SELECT id FROM users WHERE role='admin' LIMIT 1")
          .get()
      )
        throw new Error("Administrator setup is already complete.");
      const existing = initialAdmin
        ? this.store.db.prepare("SELECT id,created_at FROM users WHERE username=?").get(username) as { id: string; created_at: number } | undefined
        : undefined;
      if (existing) {
        user.id = existing.id;
        user.createdAt = existing.created_at;
        this.store.db.prepare("UPDATE users SET salt=?,password_hash=?,role='admin' WHERE id=?").run(salt, hash, existing.id);
        this.store.db.prepare("DELETE FROM sessions WHERE user_id=?").run(existing.id);
        this.store.db.exec("COMMIT");
        return user;
      }
      this.store.db
        .prepare(
          "INSERT INTO users(id,username,salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
        )
        .run(user.id, username, salt, hash, role, user.createdAt);
      this.store.db.exec("COMMIT");
      return user;
    } catch (err) {
      this.store.db.exec("ROLLBACK");
      throw err;
    }
  }
  session(token?: string) {
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const row = this.store.db
      .prepare(
        "SELECT u.*,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=? AND expires_at>?",
      )
      .get(fingerprint(token), this.now()) as
      (StoredUser & { expires_at: number }) | undefined;
    return row
      ? { user: this.publicUser(row), expiresAt: row.expires_at }
      : null;
  }
  issueSession(userId: string) {
    const token = this.token(),
      expiresAt = this.now() + this.store.policy().sessionMinutes * 60000;
    this.store.db
      .prepare("INSERT INTO sessions VALUES(?,?,?,?)")
      .run(fingerprint(token), userId, this.now(), expiresAt);
    return { token, expiresAt };
  }
  logout(token?: string) {
    if (token)
      this.store.db
        .prepare("DELETE FROM sessions WHERE token_hash=?")
        .run(fingerprint(token));
    this.onAudit();
  }
  csrf(token: string | undefined, sessionToken?: string) {
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return false;
    const sessionHash = this.session(sessionToken)
      ? fingerprint(sessionToken!)
      : null;
    const row = this.store.db
      .prepare(
        "SELECT session_hash FROM csrf WHERE token_hash=? AND expires_at>?",
      )
      .get(fingerprint(token), this.now()) as
      { session_hash: string | null } | undefined;
    return !!row && row.session_hash === sessionHash;
  }
  issueCsrf(sessionToken?: string) {
    const token = this.token(),
      session = this.session(sessionToken);
    this.store.db
      .prepare("INSERT INTO csrf VALUES(?,?,?)")
      .run(
        fingerprint(token),
        session ? fingerprint(sessionToken!) : null,
        session ? session.expiresAt : this.now() + 3600000,
      );
    return token;
  }
  consumeCsrf(token?: string) {
    if (token)
      this.store.db
        .prepare("DELETE FROM csrf WHERE token_hash=?")
        .run(fingerprint(token));
  }
  hit(bucket: string, limit: number, windowSeconds: number) {
    const n = this.now(),
      start = n - windowSeconds * 1000;
    this.store.db
      .prepare("DELETE FROM rate_hits WHERE bucket=? AND at<=?")
      .run(bucket, start);
    const data = this.store.db
      .prepare(
        "SELECT COUNT(*) count, MIN(at) first FROM rate_hits WHERE bucket=?",
      )
      .get(bucket) as { count: number; first: number | null };
    if (data.count >= limit)
      return Math.max(
        1,
        Math.ceil(((data.first || n) + windowSeconds * 1000 - n) / 1000),
      );
    this.store.db
      .prepare("INSERT INTO rate_hits(bucket,at) VALUES(?,?)")
      .run(bucket, n);
    return 0;
  }
  async login(
    username: string,
    password: string,
    ip: string,
    ipCounted = false,
  ) {
    const policy = this.store.policy(),
      key = fingerprint(username),
      now = this.now();
    const user = this.store.db
      .prepare("SELECT * FROM users WHERE username=?")
      .get(username) as StoredUser | undefined;
    const controls: string[] = [];
    const ipRetry = ipCounted
      ? 0
      : this.hit("login:ip:" + ip, policy.ipLimit, policy.rateWindowSeconds);
    const accountRetry = this.hit(
      "login:account:" + key,
      policy.accountLimit,
      policy.rateWindowSeconds,
    );
    if (ipRetry) controls.push("ip_rate_limit");
    if (accountRetry) controls.push("account_rate_limit");
    let guard = this.store.db
      .prepare("SELECT * FROM guards WHERE account_key=?")
      .get(key) as { failures: number; locked_until: number } | undefined;
    if (guard && guard.locked_until > now) controls.push("account_lockout");
    if (ipRetry || accountRetry)
      return {
        status: 429,
        outcome: "blocked" as const,
        controls,
        accountId: user?.id || null,
        retryAfter: Math.max(ipRetry, accountRetry),
      };
    if (controls.includes("account_lockout"))
      return {
        status: 401,
        outcome: "blocked" as const,
        controls,
        accountId: user?.id || null,
      };
    const hash = await passwordHash(password, user?.salt || this.neutralSalt);
    const valid = timingSafeEqual(
      hash,
      user ? Buffer.from(user.password_hash, "hex") : this.neutralHash,
    );
    // Recheck after asynchronous hashing so concurrent requests cannot bypass a newly activated lock.
    guard = this.store.db
      .prepare("SELECT * FROM guards WHERE account_key=?")
      .get(key) as { failures: number; locked_until: number } | undefined;
    if (guard && guard.locked_until > this.now())
      return {
        status: 401,
        outcome: "blocked" as const,
        controls: ["account_lockout"],
        accountId: user?.id || null,
      };
    if (!valid || !user) {
      const previous =
        guard && guard.locked_until > 0 && guard.locked_until <= this.now()
          ? 0
          : guard?.failures || 0;
      const failures = previous + 1;
      const lockedUntil =
        failures >= policy.lockThreshold
          ? this.now() + policy.lockSeconds * 1000
          : 0;
      this.store.db
        .prepare(
          "INSERT INTO guards VALUES(?,?,?,?) ON CONFLICT(account_key) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,updated_at=excluded.updated_at",
        )
        .run(key, failures, lockedUntil, this.now());
      if (lockedUntil) controls.push("account_lockout_activated");
      return {
        status: 401,
        outcome: "failure" as const,
        controls,
        accountId: user?.id || null,
      };
    }
    this.store.db.prepare("DELETE FROM guards WHERE account_key=?").run(key);
    return {
      status: 200,
      outcome: "success" as const,
      controls,
      accountId: user.id,
      user: this.publicUser(user),
    };
  }
  record(input: AuditInput) {
    const db = this.store.db;
    const sequence = (
      db.prepare("SELECT COALESCE(MAX(sequence),0)+1 n FROM audit").get() as {
        n: number;
      }
    ).n;
    db.prepare("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(
      input.id,
      sequence,
      this.now(),
      safeUsername(input.username),
      input.accountId,
      input.ip.slice(0, 64),
      input.userAgent.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 256),
      input.outcome,
      input.status,
      Math.round(Math.max(0, input.durationMs) * 100) / 100,
      JSON.stringify(input.controls),
    );
    this.store.pruneAudit(this.store.policy().retentionLimit);
    this.onAudit();
  }
  audit(query: {
    page: number;
    pageSize: number;
    outcome: string;
    username: string;
    since?: number;
  }) {
    const clauses: string[] = [];
    const values: (string | number)[] = [];
    if (query.outcome !== "all") {
      clauses.push("outcome=?");
      values.push(query.outcome);
    }
    if (query.username) {
      clauses.push("username LIKE ? ESCAPE '\\'");
      values.push("%" + query.username.replace(/[\\%_]/g, "\\$&") + "%");
    }
    if (query.since) {
      clauses.push("timestamp<=?");
      values.push(query.since);
    }
    const where = clauses.length ? " WHERE " + clauses.join(" AND ") : "";
    const total = (
      this.store.db
        .prepare("SELECT COUNT(*) count FROM audit" + where)
        .get(...values) as { count: number }
    ).count;
    const rows = this.store.db
      .prepare(
        "SELECT * FROM audit" +
          where +
          " ORDER BY sequence DESC LIMIT ? OFFSET ?",
      )
      .all(...values, query.pageSize, (query.page - 1) * query.pageSize);
    return {
      events: rows.map((row) => ({
        id: row.id,
        timestamp: row.timestamp,
        username: row.username,
        accountId: row.account_id,
        ip: row.ip,
        userAgent: row.user_agent,
        outcome: row.outcome,
        status: row.status,
        durationMs: row.duration_ms,
        controls: JSON.parse(row.controls as string),
        password: "[REDACTED]",
      })),
      total,
      page: query.page,
      pageSize: query.pageSize,
      retentionLimit: this.store.policy().retentionLimit,
    };
  }
  summary() {
    const policy = this.store.policy();
    const counts = this.store.db
      .prepare("SELECT outcome,COUNT(*) count FROM audit GROUP BY outcome")
      .all();
    const alertRows = this.store.db
      .prepare(
        "SELECT LOWER(username) username,COUNT(*) failures,MAX(timestamp) lastAt FROM audit WHERE outcome='failure' AND timestamp>? AND username<>'' GROUP BY LOWER(username) HAVING COUNT(*)>=? ORDER BY lastAt DESC LIMIT 25",
      )
      .all(
        this.now() - policy.alertWindowSeconds * 1000,
        policy.alertThreshold,
      );
    return {
      counts: Object.fromEntries(counts.map((r) => [r.outcome, r.count])),
      alerts: alertRows,
      alertWindowSeconds: policy.alertWindowSeconds,
    };
  }
  setPolicy(policy: Policy) {
    this.store.setPolicy(policy);
    this.onAudit();
  }
}
