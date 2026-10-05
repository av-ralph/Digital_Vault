import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { newDb, DataType } from "pg-mem";
import type { Pool } from "pg";
import { CloudPortal } from "./cloud.js";
import { defaults } from "./config.js";

const secret = () => randomBytes(24).toString("base64url");
function fixture() {
  const db = newDb();
  db.public.registerFunction({
    name: "hashtext",
    args: [DataType.text],
    returns: DataType.integer,
    implementation: () => 1,
  });
  db.public.registerFunction({
    name: "pg_advisory_xact_lock",
    args: [DataType.integer],
    returns: DataType.integer,
    implementation: () => 1,
  });
  db.public.none(
    readFileSync(
      new URL(
        "../netlify/database/migrations/0001_accounts.sql",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  db.public.none(
    readFileSync(
      new URL(
        "../netlify/database/migrations/0002_login_location.sql",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const adapter = db.adapters.createPg(),
    pool = new adapter.Pool() as Pool;
  let clock = Date.now();
  const portal = new CloudPortal(
    pool,
    ["https://digital-vault.example"],
    "<html>Digital_Vault</html>",
    () => clock,
  );
  const cookies = new Map<string, string>();
  let csrf = "";
  async function request(
    route: string,
    body?: unknown,
    extra: Record<string, string> = {},
    context: { ip?: string; geo?: unknown } = {},
  ) {
    const response = await portal.handle(
      new Request("https://digital-vault.example" + route, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
          ...(body === undefined
            ? {}
            : {
                Origin: "https://digital-vault.example",
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf,
              }),
          ...extra,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
      context.ip || "127.0.0.1",
      context.geo,
    );
    for (const entry of response.headers.getSetCookie()) {
      const [name, value] = entry.split(";")[0].split("=");
      cookies.set(name, value);
    }
    const text = await response.text();
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    if (data.csrfToken) csrf = data.csrfToken;
    return { status: response.status, headers: response.headers, data };
  }
  return { portal, pool, request, advance: (ms: number) => (clock += ms) };
}

test("hosted registration, role enforcement, generic failures, hashing, protected pages and redacted persistent audits", async () => {
  const f = fixture();
  try {
    assert.equal(
      (await f.request("/admin")).headers.get("location"),
      "/admin/login",
    );
    await f.request("/api/session");
    const password = secret();
    assert.equal(
      (
        await f.request("/api/register", {
          username: "registered-user",
          password,
          role: "admin",
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await f.request("/api/register", {
          username: "registered-user",
          password,
        })
      ).status,
      202,
    );
    assert.equal(
      Number(
        (await f.pool.query("SELECT COUNT(*) count FROM audit")).rows[0].count,
      ),
      0,
    );
    const stored = (await f.pool.query("SELECT * FROM users")).rows[0];
    assert.equal(stored.role, "user");
    assert.notEqual(stored.password_hash, password);
    assert.ok(stored.salt);
    const wrong = secret();
    const a = await f.request("/api/login", {
      username: "registered-user",
      password: wrong,
    });
    const b = await f.request("/api/login", {
      username: "unknown-user",
      password: wrong,
    });
    assert.deepEqual(a.data, b.data);
    assert.equal(
      (await f.request("/api/login", { username: "registered-user", password }))
        .status,
      200,
    );
    assert.equal((await f.request("/admin")).status, 403);
    assert.equal((await f.request("/api/admin/audit")).status, 403);
    const adminPassword = secret();
    await f.portal.createUser("portal-owner", adminPassword, "admin", true);
    assert.equal(
      (
        await f.request("/api/login", {
          username: "portal-owner",
          password: adminPassword,
        })
      ).status,
      200,
    );
    assert.equal((await f.request("/api/admin/events")).data.realtime, "poll");
    assert.equal((await f.request("/admin")).status, 200);
    const audit = await f.request("/api/admin/audit");
    assert.equal(audit.data.total, 4);
    assert.ok(audit.data.events.every((x: any) => x.password === "[REDACTED]"));
    assert.ok(!JSON.stringify(audit.data).includes(password));
    assert.ok(!JSON.stringify(audit.data).includes(wrong));
    assert.equal((await f.request("/api/logout", {})).status, 200);
    assert.equal((await f.request("/api/admin/events")).status, 401);
  } finally {
    await f.pool.end();
  }
});

test("hosted CSRF, trusted origins, payload limit, account lockout and session expiry", async () => {
  const f = fixture();
  try {
    const password = secret();
    await f.portal.createUser("owner-account", password, "admin", true);
    await f.request("/api/session");
    assert.equal(
      (
        await f.request(
          "/api/login",
          { username: "owner-account", password },
          { "X-CSRF-Token": "" },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await f.request(
          "/api/login",
          { username: "owner-account", password },
          { Origin: "https://other.example" },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await f.request("/api/login", {
          username: "owner-account",
          password: "x".repeat(5000),
        })
      ).status,
      413,
    );
    for (let i = 0; i < defaults.lockThreshold; i++)
      assert.equal(
        (
          await f.request("/api/login", {
            username: "owner-account",
            password: secret(),
          })
        ).status,
        401,
      );
    assert.equal(
      (await f.request("/api/login", { username: "owner-account", password }))
        .status,
      401,
    );
    f.advance(defaults.lockSeconds * 1000 + 1);
    assert.equal(
      (await f.request("/api/login", { username: "owner-account", password }))
        .status,
      200,
    );
    f.advance(defaults.sessionMinutes * 60000 + 1);
    assert.equal((await f.request("/api/admin/settings")).status, 401);
  } finally {
    await f.pool.end();
  }
});

test("hosted IP rate limits are stored in the database; users and administrator setup are never seeded", async () => {
  const f = fixture();
  try {
    assert.equal(
      Number(
        (await f.pool.query("SELECT COUNT(*) count FROM users")).rows[0].count,
      ),
      0,
    );
    await f.request("/api/session");
    for (let i = 0; i < defaults.ipLimit; i++)
      await f.request("/api/login", {
        username: `name-${i}`,
        password: secret(),
      });
    const blocked = await f.request("/api/login", {
      username: "another-name",
      password: secret(),
    });
    assert.equal(blocked.status, 429);
    assert.ok(blocked.headers.get("Retry-After"));
    const audit = await f.portal.audit({
      page: 1,
      pageSize: 100,
      outcome: "all",
      username: "",
    });
    assert.equal(audit.events.length, 31);
    assert.deepEqual(audit.events[0].controls, ["ip_rate_limit"]);
  } finally {
    await f.pool.end();
  }
});

test("hosted login records trusted approximate location and ignores browser supplied location headers", async () => {
  const f = fixture();
  try {
    await f.request("/api/session");
    const password = secret();
    await f.request("/api/register", { username: "location-user", password });
    assert.equal((await f.pool.query("SELECT * FROM audit")).rows.length, 0);
    await f.request("/api/logout", {});
    await f.request("/api/session");
    const geo = {
      city: "Manila",
      subdivision: { name: "Metro Manila" },
      country: { name: "Philippines", code: "PH" },
      latitude: 14.599512,
      longitude: 120.984222,
    };
    assert.equal(
      (
        await f.request(
          "/api/login",
          { username: "location-user", password },
          {},
          { ip: "8.8.8.8", geo },
        )
      ).status,
      200,
    );
    let rows = (await f.pool.query("SELECT * FROM audit")).rows;
    const saved = JSON.parse(rows[0].location);
    assert.equal(saved.city, "Manila");
    assert.equal(saved.region, "Metro Manila");
    assert.equal(saved.latitude, 14.6);
    assert.equal(saved.longitude, 120.98);
    assert.equal(saved.accuracy, "approximate");
    assert.equal(JSON.stringify(rows).includes(password), false);
    await f.request("/api/logout", {});
    await f.request("/api/session");
    await f.request(
      "/api/login",
      { username: "location-user", password },
      { "X-City": "Spoofed", "X-Forwarded-For": "8.8.8.8" },
      { ip: "127.0.0.1", geo },
    );
    rows = (await f.pool.query("SELECT * FROM audit")).rows;
    assert.equal(rows[1].location, null);
    assert.equal(rows.length, 2);
  } finally {
    await f.pool.end();
  }
});
