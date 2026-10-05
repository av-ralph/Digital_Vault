import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { request as httpRequest, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "./app.js";
import { defaults, type Config } from "./config.js";
import { passwordHash } from "./auth.js";
const secret = () => randomBytes(24).toString("base64url");
async function fixture(overrides: Partial<Config> = {}) {
  let now = Date.now();
  const dir = mkdtempSync(path.join(tmpdir(), "loginlab-tests-"));
  const config: Config = {
    port: 3411,
    databasePath: path.join(dir, "accounts.sqlite"),
    trustedOrigins: ["http://127.0.0.1:3411"],
    trustedProxyIps: [],
    policy: { ...defaults },
    ...overrides,
  };
  const service = createApp(config, () => now);
  const server = service.app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const clients: IncomingMessage[] = [];
  function client() {
    let cookie = "",
      csrf = "";
    return {
      get cookie() {
        return cookie;
      },
      get csrf() {
        return csrf;
      },
      async request(
        route: string,
        body?: unknown,
        extra: Record<string, string> = {},
      ) {
        const result = await new Promise<{
          status: number;
          data: any;
          headers: IncomingMessage["headers"];
        }>((resolve, reject) => {
          const req = httpRequest(
            base + route,
            {
              method: body === undefined ? "GET" : "POST",
              headers: {
                Host: "127.0.0.1:3411",
                Cookie: cookie,
                ...(body === undefined
                  ? {}
                  : {
                      Origin: "http://127.0.0.1:3411",
                      "X-CSRF-Token": csrf,
                      "Content-Type": "application/json",
                    }),
                ...extra,
              },
            },
            (res) => {
              let text = "";
              res.on("data", (c) => (text += c));
              res.on("end", () => {
                let data: any;
                try {
                  data = JSON.parse(text);
                } catch {
                  data = text;
                }
                resolve({
                  status: res.statusCode || 0,
                  data,
                  headers: res.headers,
                });
              });
            },
          );
          req.on("error", reject);
          if (body !== undefined) req.write(JSON.stringify(body));
          req.end();
        });
        for (const c of result.headers["set-cookie"] || []) {
          const pair = c.split(";")[0],
            name = pair.split("=")[0];
          cookie = cookie
            .split("; ")
            .filter((p) => p && !p.startsWith(name + "="))
            .concat(pair)
            .join("; ");
        }
        if (result.data.csrfToken) csrf = result.data.csrfToken;
        return result;
      },
      async initialize() {
        await this.request("/api/session");
      },
      async stream() {
        return new Promise<IncomingMessage>((resolve, reject) => {
          const req = httpRequest(
            base + "/api/admin/events",
            { headers: { Host: "127.0.0.1:3411", Cookie: cookie } },
            (res) => {
              clients.push(res);
              resolve(res);
            },
          );
          req.on("error", reject);
          req.end();
        });
      },
    };
  }
  return {
    service,
    config,
    dir,
    client,
    advance: (ms: number) => (now += ms),
    async close() {
      clients.forEach((c) => c.destroy());
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      service.close();
      const resolved = path.resolve(dir);
      assert.ok(
        resolved.startsWith(path.resolve(tmpdir()) + path.sep) &&
          path.basename(resolved).startsWith("loginlab-tests-"),
      );
      rmSync(resolved, { recursive: true, force: true });
    },
  };
}
test("empty database; genuine registration has no privilege escalation or audit event", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    assert.equal(
      (
        f.service.store.db.prepare("SELECT COUNT(*) n FROM users").get() as {
          n: number;
        }
      ).n,
      0,
    );
    assert.equal(
      (
        f.service.store.db.prepare("SELECT COUNT(*) n FROM audit").get() as {
          n: number;
        }
      ).n,
      0,
    );
    const password = secret();
    assert.equal(
      (
        await c.request("/api/register", {
          username: "registered-user",
          password,
          role: "admin",
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await c.request("/api/register", {
          username: "registered-user",
          password,
        })
      ).status,
      202,
    );
    const row = f.service.store.db.prepare("SELECT * FROM users").get()!;
    assert.equal(row.role, "user");
    assert.notEqual(row.password_hash, password);
    assert.equal("password" in row, false);
    assert.equal(
      f.service.auth.audit({
        page: 1,
        pageSize: 20,
        outcome: "all",
        username: "",
      }).total,
      0,
    );
    const duplicate = await c.request("/api/register", {
      username: "registered-user",
      password,
    });
    assert.equal(duplicate.status, 202);
    assert.equal(
      duplicate.data.message,
      "If this username was available, your account is ready. You can sign in.",
    );
    assert.equal(
      (await c.request("/api/login", { username: "registered-user", password }))
        .status,
      200,
    );
  } finally {
    await f.close();
  }
});
test("unique salts and scrypt hashes; initial admin setup is one-time, with no password response", async () => {
  const f = await fixture();
  try {
    const password = secret();
    await f.service.auth.createUser("first-user", password);
    await f.service.auth.createUser("second-user", password);
    const rows = f.service.store.db
      .prepare("SELECT * FROM users ORDER BY username")
      .all();
    assert.notEqual(rows[0].salt, rows[1].salt);
    assert.notEqual(rows[0].password_hash, rows[1].password_hash);
    assert.equal(
      (await passwordHash(password, rows[0].salt as string)).toString("hex"),
      rows[0].password_hash,
    );
    const admin = await f.service.auth.createUser(
      "owner-admin",
      secret(),
      "admin",
      true,
    );
    assert.equal(admin.role, "admin");
    assert.equal("password" in admin, false);
    await assert.rejects(
      f.service.auth.createUser("second-admin", secret(), "admin", true),
    );
  } finally {
    await f.close();
  }
});
test("generic errors, sanitized audit metadata, no plaintext password in database or API", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    const password = secret(),
      wrong = secret();
    await f.service.auth.createUser("account-one", password);
    const a = await c.request("/api/login", {
      username: "account-one",
      password: wrong,
    });
    const b = await c.request("/api/login", {
      username: "unknown-one",
      password: wrong,
    });
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.deepEqual(a.data, b.data);
    const good = await c.request("/api/login", {
      username: "account-one",
      password,
    });
    assert.equal(good.status, 200);
    assert.ok(!JSON.stringify(good.data).includes(password));
    assert.equal(good.data.token, undefined);
    assert.ok(
      good.headers["set-cookie"]?.some(
        (v) =>
          v.includes("HttpOnly") &&
          v.includes("Secure") &&
          v.includes("SameSite=Strict"),
      ),
    );
    const audit = f.service.auth.audit({
      page: 1,
      pageSize: 20,
      outcome: "all",
      username: "",
    });
    assert.equal(audit.total, 3);
    assert.ok(audit.events.every((e) => e.password === "[REDACTED]"));
    assert.equal(audit.events[0].accountId, good.data.user.id);
    assert.equal(audit.events[0].status, 200);
    assert.ok(Number(audit.events[0].durationMs) > 0);
    assert.ok(audit.events[0].id);
    assert.ok(!JSON.stringify(audit).includes(password));
    assert.ok(!JSON.stringify(audit).includes(wrong));
    f.service.store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    const contents = readFileSync(f.config.databasePath).toString("latin1");
    assert.ok(!contents.includes(password));
    assert.ok(!contents.includes(wrong));
    const evil = "\u0000<img src=x onerror=alert(1)>" + "x".repeat(80);
    await c.request("/api/login", { username: evil, password: wrong });
    const event = f.service.auth.audit({
      page: 1,
      pageSize: 1,
      outcome: "all",
      username: "",
    }).events[0];
    assert.equal((event.username as string).length, 64);
    assert.ok(!(event.username as string).includes("\u0000"));
  } finally {
    await f.close();
  }
});
test("server-side page/API authorization; admin provisioning and settings are protected", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    assert.equal((await c.request("/api/admin/audit")).status, 401);
    assert.equal((await c.request("/api/admin/events")).status, 401);
    assert.equal((await c.request("/account")).status, 302);
    const adminRedirect = await c.request("/admin");
    assert.equal(adminRedirect.status, 302);
    assert.equal(adminRedirect.headers.location, "/admin/login");
    assert.equal((await c.request("/admin/login")).status, 200);
    const password = secret();
    await f.service.auth.createUser("ordinary-user", password);
    await c.request("/api/login", { username: "ordinary-user", password });
    assert.equal((await c.request("/api/account")).status, 200);
    assert.equal((await c.request("/api/admin/audit")).status, 403);
    assert.equal((await c.request("/admin")).status, 403);
    assert.equal(
      (await c.request("/api/admin/settings", defaults)).status,
      403,
    );
    assert.equal(
      (
        await c.request("/api/admin/users", {
          username: "escalation",
          password: secret(),
          role: "admin",
        })
      ).status,
      403,
    );
    const admin = f.client(),
      adminPassword = secret();
    await f.service.auth.createUser(
      "admin-owner",
      adminPassword,
      "admin",
      true,
    );
    await admin.initialize();
    await admin.request("/api/login", {
      username: "admin-owner",
      password: adminPassword,
    });
    const signedInAdmin = await admin.request("/admin/login");
    assert.equal(signedInAdmin.status, 302);
    assert.equal(signedInAdmin.headers.location, "/admin");
    assert.equal(
      (
        await admin.request("/api/admin/settings", {
          ...defaults,
          retentionLimit: 100,
        })
      ).status,
      200,
    );
    const created = await admin.request("/api/admin/users", {
      username: "authorized-user",
      password: secret(),
      role: "user",
    });
    assert.equal(created.status, 201);
    assert.equal(created.data.user.role, "user");
    assert.equal((await admin.request("/api/admin/users")).data.length, 3);
  } finally {
    await f.close();
  }
});
test("session tokens are hashed; logout and expiry invalidate access and csrf", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    const password = secret();
    await f.service.auth.createUser("session-user", password);
    await c.request("/api/login", { username: "session-user", password });
    const raw = c.cookie
      .split("; ")
      .find((v) => v.startsWith("portal_session="))!
      .split("=")[1];
    const stored = f.service.store.db
      .prepare("SELECT token_hash FROM sessions")
      .get()!;
    assert.notEqual(stored.token_hash, raw);
    assert.equal((await c.request("/api/session")).data.authenticated, true);
    const expiredCsrf = c.csrf;
    await c.request("/api/logout", {});
    assert.equal(f.service.auth.session(raw), null);
    assert.equal(f.service.auth.csrf(expiredCsrf, raw), false);
    assert.equal((await c.request("/api/account")).status, 401);
    await c.initialize();
    await c.request("/api/login", { username: "session-user", password });
    f.advance(defaults.sessionMinutes * 60000);
    assert.equal((await c.request("/api/account")).status, 401);
    assert.equal((await c.request("/api/session")).data.authenticated, false);
  } finally {
    await f.close();
  }
});
test("CSRF, Origin, Host, schema and size guards; no old training endpoints", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    assert.equal(
      (
        await c.request(
          "/api/register",
          { username: "valid-name", password: secret() },
          { "X-CSRF-Token": "" },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await c.request(
          "/api/logout",
          {},
          { Origin: "http://untrusted.invalid" },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await c.request("/api/session", undefined, {
          Host: "untrusted.invalid",
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await c.request(
          "/api/login",
          { username: "valid-name", password: secret() },
          { "X-CSRF-Token": "a".repeat(64) },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await c.request("/api/login", {
          username: "valid-name",
          password: "x".repeat(5000),
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await c.request("/api/login", {
          username: "valid-name",
          password: secret(),
          extra: "unexpected",
        })
      ).status,
      400,
    );
    assert.equal((await c.request("/api/simulator")).status, 404);
    assert.equal((await c.request("/api/state")).status, 404);
    assert.equal((await c.request("/api/captcha")).status, 404);
  } finally {
    await f.close();
  }
});
test("account/IP rate limits and retry information are enforced with controllable time", async () => {
  const f = await fixture({
    policy: { ...defaults, ipLimit: 5, accountLimit: 3, lockThreshold: 20 },
  });
  try {
    const c = f.client();
    await c.initialize();
    for (let i = 0; i < 3; i++)
      assert.equal(
        (
          await c.request("/api/login", {
            username: "unknown-account",
            password: secret(),
          })
        ).status,
        401,
      );
    const blocked = await c.request("/api/login", {
      username: "unknown-account",
      password: secret(),
    });
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers["retry-after"]) > 0);
    assert.ok(blocked.data.retryAfter > 0);
    await c.request("/api/login", {
      username: "different-account",
      password: secret(),
    });
    const ipBlocked = await c.request("/api/login", {
      username: "third-account",
      password: secret(),
    });
    assert.equal(ipBlocked.status, 429);
    const latest = f.service.auth.audit({
      page: 1,
      pageSize: 1,
      outcome: "all",
      username: "",
    }).events[0];
    assert.ok(latest.controls.includes("ip_rate_limit"));
    f.advance(defaults.rateWindowSeconds * 1000);
    assert.equal(
      (
        await c.request("/api/login", {
          username: "unknown-account",
          password: secret(),
        })
      ).status,
      401,
    );
  } finally {
    await f.close();
  }
});
test("lockout activates at threshold, resists concurrency, expires; unknown names behave alike", async () => {
  const f = await fixture({
    policy: {
      ...defaults,
      accountLimit: 100,
      ipLimit: 100,
      lockThreshold: 3,
      lockSeconds: 10,
    },
  });
  try {
    const c = f.client();
    await c.initialize();
    const password = secret();
    await f.service.auth.createUser("locked-user", password);
    for (let i = 0; i < 3; i++)
      await c.request("/api/login", {
        username: "locked-user",
        password: secret(),
      });
    const known = await c.request("/api/login", {
      username: "locked-user",
      password,
    });
    assert.equal(known.status, 401);
    assert.equal(
      f.service.auth.audit({
        page: 1,
        pageSize: 1,
        outcome: "all",
        username: "",
      }).events[0].outcome,
      "blocked",
    );
    for (let i = 0; i < 3; i++)
      await c.request("/api/login", {
        username: "unknown-locked",
        password: secret(),
      });
    const unknown = await c.request("/api/login", {
      username: "unknown-locked",
      password,
    });
    assert.deepEqual(known.data, unknown.data);
    f.advance(10000);
    assert.equal(
      (await c.request("/api/login", { username: "locked-user", password }))
        .status,
      200,
    );
    await c.request("/api/login", {
      username: "locked-user",
      password: secret(),
    });
    assert.equal(
      (await c.request("/api/login", { username: "locked-user", password }))
        .status,
      200,
    );
    const fresh = f.service.store.db
      .prepare("SELECT * FROM guards WHERE account_key=?")
      .get("unused");
    assert.equal(fresh, undefined);
  } finally {
    await f.close();
  }
});
test("failure alerts, retention, filtering and pagination use only recorded requests", async () => {
  const f = await fixture({
    policy: { ...defaults, ipLimit: 100, accountLimit: 100, lockThreshold: 20 },
  });
  try {
    const c = f.client();
    await c.initialize();
    for (let i = 0; i < 4; i++)
      await c.request("/api/login", {
        username: "alerted-account",
        password: secret(),
      });
    assert.equal(f.service.auth.summary().alerts[0].failures, 4);
    const first = f.service.auth.audit({
      page: 1,
      pageSize: 2,
      outcome: "failure",
      username: "alerted",
    });
    const second = f.service.auth.audit({
      page: 2,
      pageSize: 2,
      outcome: "failure",
      username: "alerted",
    });
    assert.equal(first.total, 4);
    assert.equal(first.events.length, 2);
    assert.ok(
      !second.events.some((e) =>
        first.events.some((other) => e.id === other.id),
      ),
    );
    assert.equal(
      f.service.auth.audit({
        page: 1,
        pageSize: 20,
        outcome: "failure",
        username: "%",
      }).total,
      0,
    );
    f.service.store.pruneAudit(2);
    assert.equal(
      f.service.auth.audit({
        page: 1,
        pageSize: 20,
        outcome: "all",
        username: "",
      }).total,
      2,
    );
    f.advance(defaults.alertWindowSeconds * 1000);
    assert.equal(f.service.auth.summary().alerts.length, 0);
  } finally {
    await f.close();
  }
});
test("SSE requires admin; sends genuine refreshes and closes on logout", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    const password = secret();
    await f.service.auth.createUser("stream-admin", password, "admin", true);
    await c.request("/api/login", { username: "stream-admin", password });
    const stream = await c.stream();
    assert.equal(stream.statusCode, 200);
    let text = "";
    const updated = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("No audit refresh arrived.")),
        3000,
      );
      stream.on("data", (chunk) => {
        text += chunk;
        if (text.includes("refresh")) {
          clearTimeout(timer);
          resolve();
        }
      });
    });
    const other = f.client();
    await other.initialize();
    await other.request("/api/login", {
      username: "stream-unknown",
      password: secret(),
    });
    await updated;
    assert.ok(!text.includes(password));
    assert.ok(!text.includes("stream-unknown"));
    const ended = new Promise<void>((r) => stream.once("end", r));
    await c.request("/api/logout", {});
    await ended;
    assert.equal((await c.request("/api/admin/audit")).status, 401);
  } finally {
    await f.close();
  }
});
test("socket IP is default; forwarded headers are used only for configured proxies", async () => {
  for (const trusted of [false, true]) {
    const f = await fixture({ trustedProxyIps: trusted ? ["127.0.0.1"] : [] });
    try {
      const c = f.client();
      await c.initialize();
      await c.request(
        "/api/login",
        { username: "address-user", password: secret() },
        {
          "X-Forwarded-For": "192.0.2.55",
          "User-Agent": "integration browser",
        },
      );
      const event = f.service.auth.audit({
        page: 1,
        pageSize: 1,
        outcome: "all",
        username: "",
      }).events[0];
      assert.equal(event.ip, trusted ? "192.0.2.55" : "127.0.0.1");
      assert.equal(event.userAgent, "integration browser");
    } finally {
      await f.close();
    }
  }
});
test("accounts, sessions, policies, counters and audit survive a SQLite reopen", async () => {
  const f = await fixture();
  try {
    const password = secret();
    await f.service.auth.createUser("persistent-user", password);
    const c = f.client();
    await c.initialize();
    await c.request("/api/login", { username: "persistent-user", password });
    const reopened = createApp({ ...f.config });
    try {
      const token = c.cookie
        .split("; ")
        .find((v) => v.startsWith("portal_session="))!
        .split("=")[1];
      assert.equal(
        reopened.auth.session(token)?.user.username,
        "persistent-user",
      );
      assert.equal(
        reopened.auth.audit({
          page: 1,
          pageSize: 20,
          outcome: "all",
          username: "",
        }).total,
        1,
      );
    } finally {
      reopened.close();
    }
  } finally {
    await f.close();
  }
});

test("concurrent failures cannot bypass a newly activated account lock", async () => {
  const f = await fixture({
    policy: { ...defaults, ipLimit: 100, accountLimit: 100, lockThreshold: 3 },
  });
  try {
    const c = f.client();
    await c.initialize();
    const password = secret();
    await f.service.auth.createUser("parallel-user", password);
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        c.request("/api/login", {
          username: "parallel-user",
          password: secret(),
        }),
      ),
    );
    assert.ok(results.every((r) => r.status === 401));
    assert.equal(
      (await c.request("/api/login", { username: "parallel-user", password }))
        .status,
      401,
    );
    const events = f.service.auth.audit({
      page: 1,
      pageSize: 20,
      outcome: "all",
      username: "parallel-user",
    }).events;
    assert.ok(
      events.some(
        (e) =>
          e.outcome === "blocked" && e.controls.includes("account_lockout"),
      ),
    );
    assert.equal(
      events.filter((e) => e.controls.includes("account_lockout_activated"))
        .length,
      1,
    );
  } finally {
    await f.close();
  }
});
test("retention changes through the admin API trim genuine requests immediately", async () => {
  const f = await fixture({
    policy: { ...defaults, ipLimit: 1000, accountLimit: 100 },
  });
  try {
    const c = f.client();
    await c.initialize();
    const password = secret();
    await f.service.auth.createUser("retention-admin", password, "admin", true);
    await c.request("/api/login", { username: "retention-admin", password });
    for (let i = 0; i < 104; i++)
      await c.request("/api/login", {
        username: "invalid-request",
        password: "",
      });
    assert.equal((await c.request("/api/admin/audit")).data.total, 105);
    assert.equal(
      (
        await c.request("/api/admin/settings", {
          ...f.config.policy,
          retentionLimit: 100,
        })
      ).status,
      200,
    );
    assert.equal((await c.request("/api/admin/audit")).data.total, 100);
    assert.equal(
      (await c.request("/api/admin/audit")).data.retentionLimit,
      100,
    );
  } finally {
    await f.close();
  }
});
test("administrator SSE authorization expires while the stream is open", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    const password = secret();
    await f.service.auth.createUser("expiry-admin", password, "admin", true);
    await c.request("/api/login", { username: "expiry-admin", password });
    const stream = await c.stream();
    let text = "";
    const end = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("Expired monitoring stream remained open.")),
        3000,
      );
      stream.on("data", (chunk) => (text += chunk));
      stream.once("end", () => {
        clearTimeout(timer);
        resolve();
      });
    });
    f.advance(defaults.sessionMinutes * 60000);
    await end;
    assert.ok(text.includes("event: expired"));
  } finally {
    await f.close();
  }
});

test("initial administrator setup reuses an existing account and invalidates its old access", async () => {
  const f = await fixture();
  try {
    const oldPassword = secret(),
      newPassword = secret();
    const existing = await f.service.auth.createUser(
      "registered-owner",
      oldPassword,
    );
    const session = f.service.auth.issueSession(existing.id);
    const admin = await f.service.auth.createUser(
      "registered-owner",
      newPassword,
      "admin",
      true,
    );
    assert.equal(admin.id, existing.id);
    assert.equal(admin.createdAt, existing.createdAt);
    assert.equal(admin.role, "admin");
    assert.equal(f.service.auth.session(session.token), null);
    const c = f.client();
    await c.initialize();
    assert.equal(
      (
        await c.request("/api/login", {
          username: admin.username,
          password: oldPassword,
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await c.request("/api/login", {
          username: admin.username,
          password: newPassword,
        })
      ).status,
      200,
    );
    assert.equal((await c.request("/api/admin/settings")).status, 200);
    await assert.rejects(
      f.service.auth.createUser("registered-owner", secret(), "admin", true),
    );
  } finally {
    await f.close();
  }
});

test("local login accepts an optional consented device position without changing socket IP or leaking credentials", async () => {
  const f = await fixture();
  try {
    const c = f.client();
    await c.initialize();
    const password = secret(),
      browserLocation = {
        consent: true,
        latitude: 0,
        longitude: 0,
        accuracyMeters: 25,
        collectedAt: Date.now(),
      };
    await c.request("/api/register", { username: "position-user", password });
    assert.equal(
      (
        await c.request("/api/login", {
          username: "position-user",
          password,
          browserLocation,
        })
      ).status,
      200,
    );
    const audit = f.service.auth.audit({
      page: 1,
      pageSize: 20,
      outcome: "all",
      username: "",
    });
    assert.deepEqual(audit.events[0].browserLocation, browserLocation);
    assert.equal(audit.events[0].ip, "127.0.0.1");
    assert.equal(audit.events[0].location, null);
    assert.equal(audit.events[0].password, "[REDACTED]");
    assert.equal(JSON.stringify(audit).includes(password), false);
    assert.equal((await c.request("/api/admin/audit")).status, 403);
  } finally {
    await f.close();
  }
});
