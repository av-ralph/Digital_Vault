import {
  auditLocation,
  storedBrowserLocation,
  freshBrowserLocation,
  type BrowserLocation,
  locationFromGeo,
  storedLocation,
  type LoginLocation,
} from "./location.js";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { z } from "zod";
import {
  defaults,
  policySchema,
  registrationSchema,
  loginSchema,
  safeUsername,
  type Policy,
} from "./config.js";
import { fingerprint, passwordHash } from "./password.js";

type Account = {
  id: string;
  username: string;
  salt: string;
  password_hash: string;
  role: "user" | "admin";
  created_at: number;
};
type Access = { user: Account; expiresAt: number; hash: string };
const publicUser = (u: Account) => ({
  id: u.id,
  username: u.username,
  role: u.role,
  createdAt: Number(u.created_at),
});
const token = () => randomBytes(32).toString("hex");
const generic = "Unable to sign in. Check your credentials or try again later.";
const opaque = (s?: string): s is string => !!s && /^[a-f0-9]{64}$/.test(s);
const auditQuery = z.object({
  page: z.coerce.number().int().min(1).max(100000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  outcome: z
    .enum(["all", "success", "failure", "blocked", "challenge"])
    .default("all"),
  username: z.string().max(64).default(""),
  since: z.coerce.number().positive().optional(),
});

export class CloudPortal {
  private neutralSalt = token();
  private neutralHash = randomBytes(64);
  constructor(
    readonly pool: Pool,
    readonly origins: string[],
    readonly html: string,
    readonly now = () => Date.now(),
  ) {
    if (
      !origins.length ||
      origins.some((o) => {
        try {
          const u = new URL(o);
          return (
            u.origin !== o ||
            (u.protocol !== "https:" &&
              !["127.0.0.1", "localhost"].includes(u.hostname))
          );
        } catch {
          return true;
        }
      })
    )
      throw new Error("Invalid trusted origins.");
  }
  async policy(db: Pool | PoolClient = this.pool): Promise<Policy> {
    await db.query(
      "INSERT INTO settings(id,policy) VALUES(1,$1) ON CONFLICT(id) DO NOTHING",
      [JSON.stringify(defaults)],
    );
    return policySchema.parse(
      JSON.parse(
        (await db.query("SELECT policy FROM settings WHERE id=1")).rows[0]
          .policy,
      ),
    );
  }
  async session(raw?: string): Promise<Access | null> {
    if (!opaque(raw)) return null;
    const row = (
      await this.pool.query(
        "SELECT u.*,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=$1 AND expires_at>$2",
        [fingerprint(raw), this.now()],
      )
    ).rows[0];
    return row
      ? { user: row, expiresAt: Number(row.expires_at), hash: fingerprint(raw) }
      : null;
  }
  async csrf(raw: string | undefined, access: Access | null) {
    if (!opaque(raw)) return false;
    const row = (
      await this.pool.query(
        "SELECT session_hash FROM csrf WHERE token_hash=$1 AND expires_at>$2",
        [fingerprint(raw), this.now()],
      )
    ).rows[0];
    return !!row && row.session_hash === (access?.hash || null);
  }
  async issueCsrf(access: Access | null) {
    const value = token();
    await this.pool.query("INSERT INTO csrf VALUES($1,$2,$3)", [
      fingerprint(value),
      access?.hash || null,
      access?.expiresAt || this.now() + 3600000,
    ]);
    return value;
  }
  async transaction<T>(fn: (db: PoolClient) => Promise<T>) {
    const db = await this.pool.connect();
    try {
      await db.query("BEGIN");
      const result = await fn(db);
      await db.query("COMMIT");
      return result;
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    } finally {
      db.release();
    }
  }
  async hit(db: PoolClient, bucket: string, limit: number, window: number) {
    // Transaction-scoped locks serialize shared counters across all serverless instances.
    await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [bucket]);
    await db.query("DELETE FROM rate_hits WHERE bucket=$1 AND at<=$2", [
      bucket,
      this.now() - window * 1000,
    ]);
    const data = (
      await db.query(
        "SELECT COUNT(*)::int count,MIN(at) first FROM rate_hits WHERE bucket=$1",
        [bucket],
      )
    ).rows[0];
    if (data.count >= limit)
      return Math.max(
        1,
        Math.ceil((Number(data.first) + window * 1000 - this.now()) / 1000),
      );
    await db.query("INSERT INTO rate_hits(bucket,at) VALUES($1,$2)", [
      bucket,
      this.now(),
    ]);
    return 0;
  }
  async createUser(
    username: string,
    password: string,
    role: "user" | "admin" = "user",
    initial = false,
  ) {
    const salt = token(),
      hash = (await passwordHash(password, salt)).toString("hex");
    return this.transaction(async (db) => {
      if (initial) {
        await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
          "initial-admin",
        ]);
        if (
          (await db.query("SELECT id FROM users WHERE role='admin' LIMIT 1"))
            .rows.length
        )
          throw new Error("Administrator setup is already complete.");
        const existing = (
          await db.query("SELECT * FROM users WHERE username=$1", [username])
        ).rows[0];
        if (existing) {
          await db.query(
            "UPDATE users SET salt=$1,password_hash=$2,role='admin' WHERE id=$3",
            [salt, hash, existing.id],
          );
          await db.query("DELETE FROM sessions WHERE user_id=$1", [
            existing.id,
          ]);
          return publicUser({ ...existing, role: "admin" });
        }
      }
      const user: Account = {
        id: randomUUID(),
        username,
        salt,
        password_hash: hash,
        role,
        created_at: this.now(),
      };
      await db.query("INSERT INTO users VALUES($1,$2,$3,$4,$5,$6)", [
        user.id,
        username,
        salt,
        hash,
        role,
        user.created_at,
      ]);
      return publicUser(user);
    });
  }
  async login(username: string, password: string, policy: Policy) {
    const key = fingerprint(username);
    return this.transaction(async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
        "account:" + key,
      ]);
      const user: Account | undefined = (
        await db.query("SELECT * FROM users WHERE username=$1", [username])
      ).rows[0];
      const retry = await this.hit(
        db,
        "login:account:" + key,
        policy.accountLimit,
        policy.rateWindowSeconds,
      );
      if (retry)
        return {
          status: 429,
          outcome: "blocked",
          controls: ["account_rate_limit"],
          accountId: user?.id || null,
          retry,
        };
      const guard = (
        await db.query("SELECT * FROM guards WHERE account_key=$1", [key])
      ).rows[0];
      if (guard && Number(guard.locked_until) > this.now())
        return {
          status: 401,
          outcome: "blocked",
          controls: ["account_lockout"],
          accountId: user?.id || null,
        };
      const hash = await passwordHash(password, user?.salt || this.neutralSalt);
      const valid = timingSafeEqual(
        hash,
        user ? Buffer.from(user.password_hash, "hex") : this.neutralHash,
      );
      if (!valid || !user) {
        const previous =
          guard &&
          Number(guard.locked_until) > 0 &&
          Number(guard.locked_until) <= this.now()
            ? 0
            : Number(guard?.failures || 0);
        const failures = previous + 1,
          lockedUntil =
            failures >= policy.lockThreshold
              ? this.now() + policy.lockSeconds * 1000
              : 0;
        await db.query(
          "INSERT INTO guards VALUES($1,$2,$3,$4) ON CONFLICT(account_key) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,updated_at=excluded.updated_at",
          [key, failures, lockedUntil, this.now()],
        );
        return {
          status: 401,
          outcome: "failure",
          controls: lockedUntil ? ["account_lockout_activated"] : [],
          accountId: user?.id || null,
        };
      }
      await db.query("DELETE FROM guards WHERE account_key=$1", [key]);
      return {
        status: 200,
        outcome: "success",
        controls: [],
        accountId: user.id,
        user: publicUser(user),
      };
    });
  }
  async record(
    event: {
      id: string;
      username: string;
      accountId: string | null;
      ip: string;
      userAgent: string;
      outcome: string;
      status: number;
      duration: number;
      controls: string[];
      location?: LoginLocation | null;
      browserLocation?: BrowserLocation | null;
    },
    policy: Policy,
  ) {
    await this.transaction(async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
        "audit-retention",
      ]);
      await db.query(
        "INSERT INTO audit(id,timestamp,username,account_id,ip,user_agent,outcome,status,duration_ms,controls,location) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        [
          event.id,
          this.now(),
          safeUsername(event.username),
          event.accountId,
          event.ip.slice(0, 64),
          event.userAgent.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 256),
          event.outcome,
          event.status,
          Math.round(event.duration * 100) / 100,
          JSON.stringify(event.controls),
          auditLocation(event.location, event.browserLocation),
        ],
      );
      await db.query(
        "DELETE FROM audit WHERE sequence NOT IN (SELECT sequence FROM audit ORDER BY sequence DESC LIMIT $1)",
        [policy.retentionLimit],
      );
    });
  }
  async audit(query: z.infer<typeof auditQuery>) {
    const conditions: string[] = [],
      values: (string | number)[] = [];
    if (query.outcome !== "all") {
      values.push(query.outcome);
      conditions.push(`outcome=$${values.length}`);
    }
    if (query.username) {
      values.push("%" + query.username.replace(/[\\%_]/g, "\\$&") + "%");
      conditions.push(`username ILIKE $${values.length}`);
    }
    if (query.since) {
      values.push(query.since);
      conditions.push(`timestamp<=$${values.length}`);
    }
    const where = conditions.length ? " WHERE " + conditions.join(" AND ") : "";
    const total = Number(
      (
        await this.pool.query(
          "SELECT COUNT(*) count FROM audit" + where,
          values,
        )
      ).rows[0].count,
    );
    const rows = (
      await this.pool.query(
        "SELECT * FROM audit" +
          where +
          ` ORDER BY sequence DESC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
        [...values, query.pageSize, (query.page - 1) * query.pageSize],
      )
    ).rows;
    return {
      events: rows.map((r) => ({
        id: r.id,
        timestamp: Number(r.timestamp),
        username: r.username,
        accountId: r.account_id,
        ip: r.ip,
        userAgent: r.user_agent,
        outcome: r.outcome,
        status: r.status,
        durationMs: Number(r.duration_ms),
        controls: JSON.parse(r.controls),
        password: "[REDACTED]",
        location: storedLocation(r.location),
        browserLocation: storedBrowserLocation(r.location),
      })),
      total,
      page: query.page,
      pageSize: query.pageSize,
      retentionLimit: (await this.policy()).retentionLimit,
    };
  }
  async summary() {
    const policy = await this.policy();
    const counts = (
      await this.pool.query(
        "SELECT outcome,COUNT(*) count FROM audit GROUP BY outcome",
      )
    ).rows;
    const alerts = (
      await this.pool.query(
        "SELECT LOWER(username) username,COUNT(*) failures,MAX(timestamp) last_at FROM audit WHERE outcome='failure' AND timestamp>$1 AND username<>'' GROUP BY LOWER(username) HAVING COUNT(*)>=$2 ORDER BY last_at DESC LIMIT 25",
        [this.now() - policy.alertWindowSeconds * 1000, policy.alertThreshold],
      )
    ).rows;
    return {
      counts: Object.fromEntries(
        counts.map((r) => [r.outcome, Number(r.count)]),
      ),
      alerts: alerts.map((r) => ({
        username: r.username,
        failures: Number(r.failures),
        lastAt: Number(r.last_at),
      })),
      alertWindowSeconds: policy.alertWindowSeconds,
    };
  }
  async handle(req: Request, ip = "unknown", geo?: unknown) {
    const started = performance.now(),
      url = new URL(req.url),
      path = url.pathname;
    const headers = new Headers({
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Permissions-Policy": "geolocation=(self)",
      "Referrer-Policy": "same-origin",
      "Content-Security-Policy":
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src https://www.openstreetmap.org; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    });
    const cookie = Object.fromEntries(
      (req.headers.get("cookie") || "")
        .split(";")
        .map((x) => x.trim().split("=")),
    );
    const setCookie = (name: string, value: string, maxAge: number) =>
      headers.append(
        "Set-Cookie",
        `${name}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Strict`,
      );
    const loginRequest = req.method === "POST" && path === "/api/login";
    const event = {
      id: randomUUID(),
      username: "",
      accountId: null as string | null,
      ip,
      userAgent: req.headers.get("user-agent") || "",
      outcome: "failure",
      status: 400,
      duration: 0,
      controls: [] as string[],
      location: locationFromGeo(geo, ip),
      browserLocation: null as BrowserLocation | null,
    };
    if (loginRequest) headers.set("X-Request-ID", event.id);
    let policy = defaults;
    const json = (data: unknown, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: new Headers([
          ...headers,
          ["Content-Type", "application/json"],
        ]),
      });
    const redirect = (target: string) => {
      headers.set("Location", target);
      return new Response(null, { status: 302, headers });
    };
    const reject = (control: string, status = 403) => {
      event.outcome = "blocked";
      event.controls.push(control);
      return json(
        { error: "request_rejected", message: "Request rejected." },
        status,
      );
    };
    let response: Response;
    try {
      policy = await this.policy();
      response = await (async () => {
        if (!this.origins.includes(url.origin)) return reject("untrusted_host");
        const origin = req.headers.get("origin");
        if (origin && !this.origins.includes(origin))
          return reject("untrusted_origin");
        if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && !origin)
          return reject("origin_required");
        if (origin) {
          headers.set("Access-Control-Allow-Origin", origin);
          headers.set("Access-Control-Allow-Credentials", "true");
          headers.set("Vary", "Origin");
        }
        if (req.method === "OPTIONS") {
          headers.set("Access-Control-Allow-Methods", "GET,POST");
          headers.set(
            "Access-Control-Allow-Headers",
            "Content-Type,X-CSRF-Token",
          );
          return new Response(null, { status: 204, headers });
        }
        if (!["GET", "HEAD", "POST"].includes(req.method))
          return json({ message: "Method not allowed." }, 405);
        let body: unknown;
        if (req.method === "POST") {
          // Bound streamed reads as well as declared Content-Length; never log the body.
          if (Number(req.headers.get("content-length")) > 4096)
            return reject("request_size_limit", 413);
          if (
            !(req.headers.get("content-type") || "").startsWith(
              "application/json",
            )
          )
            return reject("input_validation", 400);
          const reader = req.body?.getReader();
          let size = 0;
          const chunks: Uint8Array[] = [];
          if (reader)
            for (;;) {
              const part = await reader.read();
              if (part.done) break;
              size += part.value.length;
              if (size > 4096) {
                await reader.cancel();
                return reject("request_size_limit", 413);
              }
              chunks.push(part.value);
            }
          try {
            body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } catch {
            return reject("input_validation", 400);
          }
          if (loginRequest) {
            event.username = safeUsername(
              (body as { username?: unknown })?.username,
            );
            const retry = await this.transaction((db) =>
              this.hit(
                db,
                "login:ip:" + ip,
                policy.ipLimit,
                policy.rateWindowSeconds,
              ),
            );
            if (retry) {
              event.outcome = "blocked";
              event.controls = ["ip_rate_limit"];
              headers.set("Retry-After", String(retry));
              return json(
                { error: "login_failed", message: generic, retryAfter: retry },
                429,
              );
            }
          }
        }
        const access = await this.session(cookie.portal_session);
        if (req.method === "POST") {
          const csrfHeader = req.headers.get("x-csrf-token");
          if (
            !opaque(csrfHeader || undefined) ||
            !opaque(cookie.portal_csrf) ||
            !timingSafeEqual(
              Buffer.from(csrfHeader!),
              Buffer.from(cookie.portal_csrf),
            ) ||
            !(await this.csrf(cookie.portal_csrf, access))
          )
            return reject("csrf_rejected");
        }
        if (path === "/api/session" && req.method === "GET") {
          await this.pool.query("DELETE FROM sessions WHERE expires_at<=$1", [
            this.now(),
          ]);
          await this.pool.query("DELETE FROM csrf WHERE expires_at<=$1", [
            this.now(),
          ]);
          await this.pool.query("DELETE FROM rate_hits WHERE at<=$1", [
            this.now() - 3600000,
          ]);
          await this.pool.query(
            "DELETE FROM guards WHERE updated_at<$1 AND locked_until<=$2",
            [this.now() - 86400000, this.now()],
          );
          let csrfToken = cookie.portal_csrf;
          if (!(await this.csrf(csrfToken, access))) {
            csrfToken = await this.issueCsrf(access);
            setCookie(
              "portal_csrf",
              csrfToken,
              Math.ceil(
                ((access?.expiresAt || this.now() + 3600000) - this.now()) /
                  1000,
              ),
            );
          }
          if (!access && cookie.portal_session)
            setCookie("portal_session", "", 0);
          return json({
            authenticated: !!access,
            user: access ? publicUser(access.user) : null,
            expiresAt: access?.expiresAt || null,
            csrfToken,
            realtime: "poll",
          });
        }
        if (path === "/api/register" && req.method === "POST") {
          const retry = await this.transaction((db) =>
            this.hit(db, "register:" + ip, 5, 3600),
          );
          if (retry) {
            headers.set("Retry-After", String(retry));
            return json({ message: "Please try again later." }, 429);
          }
          const data = registrationSchema.safeParse(body);
          if (!data.success)
            return json(
              {
                message:
                  "Use a valid username and a password of 15–128 characters.",
              },
              400,
            );
          try {
            await this.createUser(data.data.username, data.data.password);
          } catch (e) {
            if ((e as { code?: string }).code !== "23505") throw e;
          }
          return json(
            {
              message:
                "Registration received. You may now sign in with your account credentials.",
            },
            202,
          );
        }
        if (loginRequest) {
          const data = loginSchema.safeParse(body);
          if (!data.success) {
            event.controls.push("input_validation");
            return json({ message: generic, error: "login_failed" }, 400);
          }
          event.browserLocation = freshBrowserLocation(
            data.data.browserLocation,
            this.now(),
          );
          const result = await this.login(
            data.data.username,
            data.data.password,
            policy,
          );
          event.accountId = result.accountId;
          event.outcome = result.outcome;
          event.controls = result.controls;
          if (result.status !== 200) {
            if (result.retry) headers.set("Retry-After", String(result.retry));
            return json(
              {
                error: "login_failed",
                message: generic,
                ...(result.retry ? { retryAfter: result.retry } : {}),
              },
              result.status,
            );
          }
          if (opaque(cookie.portal_session))
            await this.pool.query("DELETE FROM sessions WHERE token_hash=$1", [
              fingerprint(cookie.portal_session),
            ]);
          const value = token(),
            expiresAt = this.now() + policy.sessionMinutes * 60000;
          await this.pool.query("INSERT INTO sessions VALUES($1,$2,$3,$4)", [
            fingerprint(value),
            result.user!.id,
            this.now(),
            expiresAt,
          ]);
          const newAccess = await this.session(value),
            csrfToken = await this.issueCsrf(newAccess);
          setCookie("portal_session", value, policy.sessionMinutes * 60);
          setCookie("portal_csrf", csrfToken, policy.sessionMinutes * 60);
          return json({
            message: "Signed in.",
            user: result.user,
            expiresAt,
            csrfToken,
          });
        }
        if (path === "/api/logout" && req.method === "POST") {
          z.object({}).strict().parse(body);
          if (opaque(cookie.portal_session))
            await this.pool.query("DELETE FROM sessions WHERE token_hash=$1", [
              fingerprint(cookie.portal_session),
            ]);
          if (opaque(cookie.portal_csrf))
            await this.pool.query("DELETE FROM csrf WHERE token_hash=$1", [
              fingerprint(cookie.portal_csrf),
            ]);
          setCookie("portal_session", "", 0);
          setCookie("portal_csrf", "", 0);
          return json({ message: "Signed out." });
        }
        const admin =
          path.startsWith("/api/admin/") ||
          ["/admin", "/admin/settings", "/instructor"].includes(path);
        const protectedRoute =
          admin || ["/api/account", "/api/access", "/account"].includes(path);
        if (protectedRoute && !access)
          return path.startsWith("/api/")
            ? json({ message: "Sign in to continue." }, 401)
            : redirect(admin ? "/admin/login" : "/login");
        if (admin && access?.user.role !== "admin")
          return json({ message: "Administrator access required." }, 403);
        if (path === "/api/account" && req.method === "GET")
          return json({
            user: publicUser(access!.user),
            expiresAt: access!.expiresAt,
          });
        if (path === "/api/access" && req.method === "GET")
          return url.searchParams.get("role") === "admin" &&
            access?.user.role !== "admin"
            ? json({ message: "Administrator access required." }, 403)
            : json({ allowed: true });
        if (path === "/api/admin/settings") {
          if (req.method === "GET") return json(policy);
          if (req.method === "POST") {
            const next = policySchema.parse(body);
            await this.transaction(async (db) => {
              await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
                "audit-retention",
              ]);
              await db.query("UPDATE settings SET policy=$1 WHERE id=1", [
                JSON.stringify(next),
              ]);
              await db.query(
                "DELETE FROM audit WHERE sequence NOT IN (SELECT sequence FROM audit ORDER BY sequence DESC LIMIT $1)",
                [next.retentionLimit],
              );
            });
            return json({ message: "Security policy saved." });
          }
        }
        if (path === "/api/admin/users") {
          if (req.method === "GET")
            return json(
              (
                await this.pool.query(
                  "SELECT id,username,role,created_at FROM users ORDER BY created_at DESC LIMIT 100",
                )
              ).rows.map(publicUser),
            );
          if (req.method === "POST") {
            const data = registrationSchema
              .extend({ role: z.enum(["user", "admin"]) })
              .parse(body);
            try {
              return json(
                {
                  message: "Account created.",
                  user: await this.createUser(
                    data.username,
                    data.password,
                    data.role,
                  ),
                },
                201,
              );
            } catch (e) {
              if ((e as { code?: string }).code === "23505")
                return json(
                  { message: "This username is already in use." },
                  409,
                );
              throw e;
            }
          }
        }
        if (path === "/api/admin/audit" && req.method === "GET")
          return json(
            await this.audit(
              auditQuery.parse(Object.fromEntries(url.searchParams)),
            ),
          );
        if (path === "/api/admin/summary" && req.method === "GET")
          return json(await this.summary());
        if (path === "/api/admin/events" && req.method === "GET")
          return json({ type: "connected", at: this.now(), realtime: "poll" });
        if (!["GET", "HEAD"].includes(req.method))
          return json({ message: "Endpoint not found." }, 404);
        if (path === "/admin/login" && access?.user.role === "admin")
          return redirect("/admin");
        if (
          [
            "/",
            "/login",
            "/register",
            "/admin/login",
            "/account",
            "/admin",
            "/admin/settings",
            "/instructor",
          ].includes(path)
        ) {
          headers.set("Content-Type", "text/html; charset=utf-8");
          return new Response(req.method === "HEAD" ? null : this.html, {
            headers,
          });
        }
        return json({ message: "Page not found." }, 404);
      })();
    } catch (e) {
      response = json(
        {
          message:
            e instanceof z.ZodError
              ? "Invalid input."
              : "The request could not be completed.",
        },
        e instanceof z.ZodError ? 400 : 503,
      );
    }
    if (loginRequest) {
      event.status = response.status;
      event.duration = performance.now() - started;
      try {
        await this.record(event, policy);
      } catch {
        return json({ message: "The request could not be completed." }, 503);
      }
    }
    return response;
  }
}
