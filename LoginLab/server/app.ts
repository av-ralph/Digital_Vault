import { freshBrowserLocation } from "./location.js";
import express from "express";
import { z } from "zod";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  configuration,
  loginSchema,
  registrationSchema,
  policySchema,
  safeUsername,
  type Config,
} from "./config.js";
import { Store } from "./store.js";
import { Auth, type AuditInput } from "./auth.js";
const genericLogin =
  "Unable to sign in. Check your credentials or try again later.";
function cookies(req: express.Request) {
  return Object.fromEntries(
    (req.headers.cookie || "").split(";").map((v) => v.trim().split("=")),
  );
}
const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "strict" as const,
  path: "/",
};
export function createApp(
  config: Config = configuration(),
  now = () => Date.now(),
) {
  const store = new Store(config.databasePath, config.policy),
    auth = new Auth(store, now),
    app = express();
  app.disable("x-powered-by");
  const normalized = (ip: string) => ip.replace(/^::ffff:/, "");
  app.set(
    "trust proxy",
    config.trustedProxyIps.length
      ? (ip: string) => config.trustedProxyIps.includes(normalized(ip))
      : false,
  );
  const ipOf = (req: express.Request) =>
    config.trustedProxyIps.length
      ? req.ip || req.socket.remoteAddress || "unknown"
      : req.socket.remoteAddress || "unknown";
  const clients = new Set<{
    res: express.Response;
    token: string;
    timer: ReturnType<typeof setInterval>;
  }>();
  const sendRefresh = () => {
    for (const c of clients) {
      if (auth.session(c.token)?.user.role !== "admin") {
        clearInterval(c.timer);
        c.res.end();
        clients.delete(c);
      } else
        c.res.write(
          `data: ${JSON.stringify({ type: "refresh", at: now() })}\n\n`,
        );
    }
  };
  auth.onAudit = sendRefresh;
  app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Permissions-Policy", "geolocation=(self)");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src https://www.openstreetmap.org; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    );
    if (req.method === "POST" && req.path === "/api/login") {
      const start = performance.now();
      res.locals.audit = {
        id: randomUUID(),
        username: "",
        accountId: null,
        ip: ipOf(req),
        userAgent: req.headers["user-agent"] || "",
        outcome: "failure",
        status: 400,
        durationMs: 0,
        controls: [],
      } satisfies AuditInput;
      res.setHeader("X-Request-ID", res.locals.audit.id);
      res.on("finish", () => {
        const data = res.locals.audit as AuditInput;
        data.status = res.statusCode;
        data.durationMs = performance.now() - start;
        try {
          auth.record(data);
        } catch {
          console.error(
            "Audit storage failed. No credential contents were written to the console.",
          );
        }
      });
    }
    next();
  });
  const hosts = new Set([
    `127.0.0.1:${config.port}`,
    ...config.trustedOrigins.map((o) => new URL(o).host),
  ]);
  function deny(res: express.Response, control: string, status = 403) {
    if (res.locals.audit) {
      res.locals.audit.outcome = "blocked";
      res.locals.audit.controls.push(control);
    }
    return res
      .status(status)
      .json({ error: "request_rejected", message: "Request rejected." });
  }
  app.use((req, res, next) => {
    if (!hosts.has(req.headers.host || "")) return deny(res, "untrusted_host");
    const origin = req.headers.origin;
    if (origin && !config.trustedOrigins.includes(origin))
      return deny(res, "untrusted_origin");
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && !origin)
      return deny(res, "origin_required");
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Methods", "GET,POST");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type,X-CSRF-Token",
      );
      return res.sendStatus(204);
    }
    next();
  });
  app.use(express.json({ limit: "4kb", strict: true }));
  app.use((req, res, next) => {
    if (res.locals.audit) {
      res.locals.audit.username = safeUsername(req.body?.username);
      const policy = store.policy();
      const retry = auth.hit(
        "login:ip:" + ipOf(req),
        policy.ipLimit,
        policy.rateWindowSeconds,
      );
      if (retry) {
        res.locals.audit.outcome = "blocked";
        res.locals.audit.controls = ["ip_rate_limit"];
        res.setHeader("Retry-After", retry);
        return res.status(429).json({
          error: "login_failed",
          message: genericLogin,
          retryAfter: retry,
        });
      }
    }
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      const c = cookies(req),
        header = req.headers["x-csrf-token"];
      if (
        typeof header !== "string" ||
        !/^[a-f0-9]{64}$/.test(header) ||
        !c.portal_csrf ||
        header.length !== c.portal_csrf.length ||
        !timingSafeEqual(Buffer.from(header), Buffer.from(c.portal_csrf)) ||
        !auth.csrf(header, c.portal_session)
      )
        return deny(res, "csrf_rejected");
    }
    next();
  });
  const requireUser: express.RequestHandler = (req, res, next) => {
    const session = auth.session(cookies(req).portal_session);
    if (!session)
      return res
        .status(401)
        .json({ error: "authentication_required", message: "Please sign in." });
    res.locals.session = session;
    next();
  };
  const requireAdmin: express.RequestHandler = (req, res, next) => {
    if (res.locals.session?.user.role !== "admin")
      return res.status(403).json({
        error: "forbidden",
        message: "Administrator access required.",
      });
    next();
  };
  function issueCsrf(
    req: express.Request,
    res: express.Response,
    sessionToken?: string,
  ) {
    const current = cookies(req).portal_csrf;
    auth.consumeCsrf(current);
    const token = auth.issueCsrf(sessionToken);
    res.cookie("portal_csrf", token, { ...cookieOptions, maxAge: 3600000 });
    return token;
  }
  app.get("/api/session", (req, res) => {
    const c = cookies(req),
      session = auth.session(c.portal_session);
    let csrfToken = c.portal_csrf;
    if (!auth.csrf(csrfToken, c.portal_session))
      csrfToken = issueCsrf(req, res, session ? c.portal_session : undefined);
    if (c.portal_session && !session)
      res.clearCookie("portal_session", cookieOptions);
    res.json({
      authenticated: !!session,
      user: session?.user || null,
      expiresAt: session?.expiresAt || null,
      csrfToken,
    });
  });
  app.post("/api/register", async (req, res) => {
    const body = registrationSchema.safeParse(req.body);
    if (!body.success)
      return res.status(400).json({
        error: "validation",
        message:
          "Use a 3–32 character username (letters, digits, dot, underscore, hyphen) and a password of 15–128 characters.",
      });
    const retry = auth.hit("registration:ip:" + ipOf(req), 5, 3600);
    if (retry) {
      res.setHeader("Retry-After", retry);
      return res.status(429).json({
        error: "rate_limited",
        message: "Please try again later.",
        retryAfter: retry,
      });
    }
    try {
      await auth.createUser(body.data.username, body.data.password, "user");
    } catch (err) {
      if (!(err instanceof Error && err.message.includes("UNIQUE constraint")))
        throw err;
    }
    res.status(202).json({
      message:
        "If this username was available, your account is ready. You can sign in.",
    });
  });
  app.post("/api/login", async (req, res) => {
    const body = loginSchema.safeParse(req.body);
    if (!body.success) {
      res.locals.audit.controls.push("input_validation");
      return res
        .status(400)
        .json({ error: "login_failed", message: genericLogin });
    }
    res.locals.audit.browserLocation = freshBrowserLocation(
      body.data.browserLocation,
      now(),
    );
    const result = await auth.login(
      body.data.username,
      body.data.password,
      ipOf(req),
      true,
    );
    Object.assign(res.locals.audit, {
      accountId: result.accountId,
      outcome: result.outcome,
      controls: result.controls,
    });
    if (result.status !== 200) {
      if (result.retryAfter) res.setHeader("Retry-After", result.retryAfter);
      return res.status(result.status).json({
        error: "login_failed",
        message: genericLogin,
        ...(result.retryAfter ? { retryAfter: result.retryAfter } : {}),
      });
    }
    auth.logout(cookies(req).portal_session);
    const session = auth.issueSession(result.accountId!);
    res.cookie("portal_session", session.token, {
      ...cookieOptions,
      maxAge: session.expiresAt - now(),
    });
    const csrfToken = issueCsrf(req, res, session.token);
    res.json({
      message: "Signed in.",
      user: result.user,
      expiresAt: session.expiresAt,
      csrfToken,
    });
  });
  app.post("/api/logout", (req, res) => {
    z.object({}).strict().parse(req.body);
    const c = cookies(req);
    auth.logout(c.portal_session);
    auth.consumeCsrf(c.portal_csrf);
    res.clearCookie("portal_session", cookieOptions);
    res.clearCookie("portal_csrf", cookieOptions);
    res.json({ message: "Signed out." });
  });
  app.get("/api/account", requireUser, (_req, res) =>
    res.json(res.locals.session),
  );
  app.get("/api/access", requireUser, (req, res) => {
    if (req.query.role === "admin" && res.locals.session.user.role !== "admin")
      return res.status(403).json({
        error: "forbidden",
        message: "Administrator access required.",
      });
    res.json({ allowed: true });
  });
  app.use("/api/admin", requireUser, requireAdmin);
  const auditQuery = z
    .object({
      page: z.coerce.number().int().min(1).max(100000).default(1),
      pageSize: z.coerce.number().int().min(1).max(100).default(20),
      outcome: z
        .enum(["all", "success", "failure", "blocked", "challenge"])
        .default("all"),
      username: z.string().max(64).default(""),
      since: z.coerce.number().int().positive().optional(),
    })
    .strict();
  app.get("/api/admin/audit", (req, res) =>
    res.json(auth.audit(auditQuery.parse(req.query))),
  );
  app.get("/api/admin/summary", (_req, res) => res.json(auth.summary()));
  app.get("/api/admin/settings", (_req, res) => res.json(store.policy()));
  app.post("/api/admin/settings", (req, res) => {
    const policy = policySchema.parse(req.body);
    auth.setPolicy(policy);
    res.json({ message: "Security policy saved.", policy });
  });
  app.get("/api/admin/users", (_req, res) =>
    res.json(
      store.db
        .prepare(
          "SELECT id,username,role,created_at AS createdAt FROM users ORDER BY created_at DESC LIMIT 100",
        )
        .all(),
    ),
  );
  app.post("/api/admin/users", async (req, res) => {
    const b = registrationSchema
      .extend({ role: z.enum(["user", "admin"]) })
      .strict()
      .parse(req.body);
    const retry = auth.hit(
      "admin:create:" + res.locals.session.user.id,
      20,
      60,
    );
    if (retry)
      return res
        .status(429)
        .json({ error: "rate_limited", message: "Please try again later." });
    try {
      const user = await auth.createUser(b.username, b.password, b.role);
      res.status(201).json({ message: "Account created.", user });
    } catch (err) {
      if (err instanceof Error && err.message.includes("UNIQUE constraint"))
        return res.status(409).json({
          error: "account_creation_failed",
          message: "Account could not be created.",
        });
      throw err;
    }
  });
  app.get("/api/admin/events", (req, res) => {
    const token = cookies(req).portal_session;
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();
    res.write('data: {"type":"connected"}\n\n');
    const client = {
      res,
      token,
      timer: setInterval(() => {
        if (auth.session(token)?.user.role !== "admin") {
          res.write("event: expired\ndata: {}\n\n");
          res.end();
        } else res.write(": heartbeat\n\n");
      }, 1000),
    };
    client.timer.unref();
    clients.add(client);
    req.on("close", () => {
      clearInterval(client.timer);
      clients.delete(client);
    });
  });
  app.use("/api", (_req, res) =>
    res
      .status(404)
      .json({ error: "not_found", message: "Endpoint not found." }),
  );
  const dist = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../dist",
  );
  app.use(
    "/assets",
    express.static(path.join(dist, "assets"), { index: false }),
  );
  app.get("/favicon.svg", (_req, res) =>
    res.sendFile(path.join(dist, "favicon.svg")),
  );
  const protectedPage: express.RequestHandler = (req, res, next) => {
    const session = auth.session(cookies(req).portal_session);
    if (!session)
      return res.redirect(req.path === "/account" ? "/login" : "/admin/login");
    if (
      ["/admin", "/admin/settings", "/instructor"].includes(req.path) &&
      session.user.role !== "admin"
    )
      return res.status(403).send("Administrator access required.");
    next();
  };
  app.get(
    ["/account", "/admin", "/admin/settings", "/instructor"],
    protectedPage,
    (_req, res) => res.sendFile(path.join(dist, "index.html")),
  );
  app.get("/admin/login", (req, res) => {
    const session = auth.session(cookies(req).portal_session);
    if (session?.user.role === "admin") return res.redirect("/admin");
    res.sendFile(path.join(dist, "index.html"));
  });
  app.get(["/", "/login", "/register"], (_req, res) =>
    res.sendFile(path.join(dist, "index.html")),
  );
  app.use((_req, res) =>
    res.status(404).json({ error: "not_found", message: "Page not found." }),
  );
  app.use(
    (
      err: unknown,
      req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      if (res.headersSent) return res.end();
      const validation =
        err instanceof z.ZodError ||
        err instanceof SyntaxError ||
        (typeof err === "object" &&
          err !== null &&
          "type" in err &&
          ["entity.too.large", "entity.parse.failed"].includes(
            String(err.type),
          ));
      if (res.locals.audit) {
        res.locals.audit.username = safeUsername(req.body?.username);
        res.locals.audit.controls.push(
          validation ? "input_validation" : "server_error",
        );
      }
      res.status(validation ? 400 : 500).json({
        error: validation ? "validation" : "server_error",
        message:
          req.path === "/api/login"
            ? genericLogin
            : validation
              ? "Invalid request."
              : "The request could not be completed.",
      });
    },
  );
  const maintenance = setInterval(() => {
    store.prune(now());
  }, 60000);
  maintenance.unref();
  return {
    app,
    auth,
    store,
    close: () => {
      clearInterval(maintenance);
      for (const c of clients) {
        clearInterval(c.timer);
        c.res.end();
      }
      clients.clear();
      store.close();
    },
  };
}
