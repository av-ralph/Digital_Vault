import { useCallback, useEffect, useRef, useState } from "react";
import {
  Shield,
  LogIn,
  UserPlus,
  UserRound,
  Activity,
  Settings,
  LogOut,
  Eye,
  EyeOff,
  Radio,
  Clock,
  LockKeyhole,
  ChevronLeft,
  ChevronRight,
  Users,
} from "lucide-react";
type User = {
  id: string;
  username: string;
  role: "user" | "admin";
  createdAt: number;
};
type Session = {
  authenticated: boolean;
  user: User | null;
  expiresAt: number | null;
  csrfToken: string;
  realtime?: "poll";
};
type Event = {
  id: string;
  timestamp: number;
  username: string;
  accountId: string | null;
  ip: string;
  userAgent: string;
  outcome: string;
  status: number;
  durationMs: number;
  controls: string[];
  password: "[REDACTED]";
};
type Audit = {
  events: Event[];
  total: number;
  page: number;
  pageSize: number;
  retentionLimit: number;
};
type Policy = {
  ipLimit: number;
  accountLimit: number;
  rateWindowSeconds: number;
  lockThreshold: number;
  lockSeconds: number;
  alertThreshold: number;
  alertWindowSeconds: number;
  sessionMinutes: number;
  retentionLimit: number;
};
type Summary = {
  counts: Record<string, number>;
  alerts: { username: string; failures: number; lastAt: number }[];
  alertWindowSeconds: number;
};
const fieldLabels: Record<keyof Policy, [string, string, number, number]> = {
  ipLimit: ["Attempts per client IP", "Within the rate window", 5, 1000],
  accountLimit: [
    "Attempts per account name",
    "Applies equally to existing and unknown names",
    3,
    100,
  ],
  rateWindowSeconds: [
    "Rate window (seconds)",
    "Window for both rate limits",
    10,
    3600,
  ],
  lockThreshold: [
    "Consecutive failures before lockout",
    "Correct authentication clears the counter",
    3,
    20,
  ],
  lockSeconds: [
    "Lockout duration (seconds)",
    "A temporary block after repeated failures",
    10,
    3600,
  ],
  alertThreshold: [
    "Failures before an alert",
    "Detection is separate from blocking",
    2,
    50,
  ],
  alertWindowSeconds: [
    "Alert window (seconds)",
    "Group repeated failures in this period",
    30,
    86400,
  ],
  sessionMinutes: [
    "New session lifetime (minutes)",
    "Existing sessions keep their original expiry",
    5,
    1440,
  ],
  retentionLimit: [
    "Retained login events",
    "Oldest events are removed when this limit is exceeded",
    100,
    50000,
  ],
};
class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
const date = (n: number) => new Date(n).toLocaleString();
export default function App() {
  const pathname = location.pathname;
  const adminSignIn = pathname === "/admin/login";
  const page =
    pathname === "/instructor"
      ? "/admin"
      : pathname === "/admin/login"
        ? "/login"
        : pathname;
  const [session, setSession] = useState<Session | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [message, setMessage] = useState(""),
    [visible, setVisible] = useState(false),
    [connection, setConnection] = useState("Connecting"),
    [revision, setRevision] = useState(0),
    [clock, setClock] = useState(Date.now());
  const csrf = useRef("");
  const [audit, setAudit] = useState<Audit | null>(null),
    [summary, setSummary] = useState<Summary | null>(null),
    [auditLoading, setAuditLoading] = useState(false),
    [outcome, setOutcome] = useState("all"),
    [search, setSearch] = useState(""),
    [draftSearch, setDraftSearch] = useState(""),
    [pageNumber, setPageNumber] = useState(1),
    [pageSize, setPageSize] = useState(20),
    [snapshot, setSnapshot] = useState<number | undefined>(),
    [policy, setPolicy] = useState<Policy | null>(null),
    [users, setUsers] = useState<User[]>([]),
    [refreshUsers, setRefreshUsers] = useState(0);
  const request = useCallback(async (path: string, body?: unknown) => {
    const response = await fetch(
      "/api" + path,
      body === undefined
        ? { cache: "no-store" }
        : {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrf.current,
            },
            body: JSON.stringify(body),
          },
    );
    const data = await response.json();
    if (!response.ok)
      throw new ApiError(
        data.message || "The request could not be completed.",
        response.status,
      );
    if (data.csrfToken) csrf.current = data.csrfToken;
    return data;
  }, []);
  useEffect(() => {
    let active = true;
    request("/session")
      .then((data) => {
        if (active) setSession(data);
      })
      .catch(() => {
        if (active)
          setError(
            "Cannot connect to the local server. Check that it is running.",
          );
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [request]);
  useEffect(() => {
    if (!session?.authenticated) return;
    if (session.expiresAt && clock >= session.expiresAt) {
      csrf.current = "";
      setSession({ ...session, authenticated: false, user: null });
      location.replace("/login?expired=1");
    }
  }, [clock, session]);
  useEffect(() => {
    if (loading || !session) return;
    if (
      ["/account", "/admin", "/admin/settings"].includes(page) &&
      !session.authenticated
    )
      location.replace(page === "/account" ? "/login" : "/admin/login");
    if (
      ["/admin", "/admin/settings"].includes(page) &&
      session.user?.role !== "admin"
    )
      location.replace("/account");
  }, [loading, session, page]);
  useEffect(() => {
    if (session?.user?.role !== "admin" || page !== "/admin") return;
    if (session.realtime === "poll") {
      let active = true,
        inFlight = false;
      const check = async () => {
        if (inFlight) return;
        inFlight = true;
        try {
          await request("/admin/events");
          if (active) {
            setConnection("Live · updates every 5 seconds");
            setRevision((v) => v + 1);
          }
        } catch (err) {
          if (active) setConnection("Disconnected · retrying");
          if (err instanceof ApiError && [401, 403].includes(err.status))
            location.replace("/admin/login?expired=1");
        } finally {
          inFlight = false;
        }
      };
      void check();
      const timer = setInterval(() => void check(), 5000);
      return () => {
        active = false;
        clearInterval(timer);
      };
    }
    const events = new EventSource("/api/admin/events");
    events.onopen = () => setConnection("Live");
    events.onmessage = () => setRevision((v) => v + 1);
    events.onerror = () => {
      setConnection("Disconnected · reconnecting");
      request("/session")
        .then((data) => {
          if (!data.authenticated || data.user?.role !== "admin")
            location.replace("/login?expired=1");
        })
        .catch(() => {});
    };
    events.addEventListener("expired", () =>
      location.replace("/login?expired=1"),
    );
    const timer = setInterval(() => setRevision((v) => v + 1), 60000);
    return () => {
      events.close();
      clearInterval(timer);
    };
  }, [session?.user?.role, session?.realtime, page, request]);
  useEffect(() => {
    if (session?.user?.role !== "admin" || page !== "/admin") return;
    let active = true;
    setAuditLoading(true);
    const query = new URLSearchParams({
      page: String(pageNumber),
      pageSize: String(pageSize),
      outcome,
      username: search,
      ...(snapshot ? { since: String(snapshot) } : {}),
    });
    Promise.all([request("/admin/audit?" + query), request("/admin/summary")])
      .then(([a, s]) => {
        if (active) {
          setAudit(a);
          setSummary(s);
          setError("");
        }
      })
      .catch((err) => {
        if (active) {
          setError(err.message);
          if (err.status === 401) location.replace("/login?expired=1");
        }
      })
      .finally(() => {
        if (active) setAuditLoading(false);
      });
    return () => {
      active = false;
    };
  }, [
    session?.user?.role,
    page,
    request,
    revision,
    pageNumber,
    pageSize,
    outcome,
    search,
    snapshot,
  ]);
  useEffect(() => {
    if (session?.user?.role !== "admin" || page !== "/admin/settings") return;
    let active = true;
    Promise.all([request("/admin/settings"), request("/admin/users")])
      .then(([p, u]) => {
        if (active) {
          setPolicy(p);
          setUsers(u);
        }
      })
      .catch((err) => {
        if (active) setError(err.message);
      });
    return () => {
      active = false;
    };
  }, [session?.user?.role, page, request, refreshUsers]);
  async function submit(path: string, body: unknown) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const data = await request(path, body);
      setMessage(data.message || "Saved.");
      return data;
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed.");
      if (err instanceof ApiError && err.status === 403) {
        request("/session")
          .then((data) => setSession(data))
          .catch(() => {});
      }
      return null;
    } finally {
      setBusy(false);
    }
  }
  async function authentication(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget,
      data = new FormData(form);
    const username = String(data.get("username") || ""),
      password = String(data.get("password") || "");
    (form.elements.namedItem("password") as HTMLInputElement).value = "";
    const result = await submit(page === "/register" ? "/register" : "/login", {
      username,
      password,
    });
    if (result && page !== "/register") {
      if (adminSignIn && result.user.role !== "admin") {
        setSession({
          authenticated: true,
          user: result.user,
          expiresAt: result.expiresAt,
          csrfToken: result.csrfToken,
        });
        setMessage("");
        setError(
          "This account does not have administrator access. You can continue to your account below.",
        );
        return;
      }
      location.assign(result.user.role === "admin" ? "/admin" : "/account");
    }
  }
  const user = session?.user;
  const isAdmin = user?.role === "admin";
  const onAccount = page === "/account";
  const onDashboard = page === "/admin";
  const onSettings = page === "/admin/settings";
  const registration = page === "/register";
  const title = onDashboard
    ? "Security monitoring"
    : onSettings
      ? "Administration"
      : onAccount
        ? "Your account"
        : registration
          ? "Create an account"
          : adminSignIn
            ? "Administrator sign in"
            : "Sign in";
  const links = user
    ? [
        { href: "/account", label: "Account", icon: UserRound },
        ...(isAdmin
          ? [
              { href: "/admin", label: "Login monitoring", icon: Activity },
              {
                href: "/admin/settings",
                label: "Administration",
                icon: Settings,
              },
            ]
          : []),
      ]
    : [
        { href: "/login", label: "Sign in", icon: LogIn },
        { href: "/register", label: "Create account", icon: UserPlus },
        {
          href: "/admin/login",
          label: "Administrator sign in",
          icon: Settings,
        },
      ];
  return (
    <div
      className={
        "app " +
        (!onAccount && !onDashboard && !onSettings
          ? "public-page"
          : "service-page")
      }
    >
      <aside>
        <a className="brand" href="/">
          <Shield size={31} />
          <span>
            Digital_Vault
            <small>Account services</small>
          </span>
        </a>
        <div className="nav-label">PORTAL</div>
        <nav>
          {links.map(({ href, label, icon: Icon }) => (
            <a
              key={href}
              href={href}
              className={
                pathname === href || (page === "/" && href === "/login")
                  ? "active"
                  : ""
              }
            >
              <Icon size={19} />
              {label}
            </a>
          ))}
        </nav>
        <div className="sidebar-footer">
          <LockKeyhole size={18} />
          <div>
            {user ? user.username : "Private account access"}
            <small>
              {user
                ? isAdmin
                  ? "Administrator"
                  : "Standard account"
                : "Protected sessions"}
            </small>
          </div>
        </div>
        {user && (
          <button
            className="secondary signout"
            disabled={busy}
            onClick={async () => {
              const result = await submit("/logout", {});
              if (result) {
                csrf.current = "";
                location.assign("/login");
              }
            }}
          >
            <LogOut size={16} />
            Sign out
          </button>
        )}
      </aside>
      <div className="workspace">
        <header>
          <span>
            PORTAL <span className="muted">/ {title}</span>
          </span>
          <span className="badge">
            {user ? (isAdmin ? "ADMINISTRATOR" : "MEMBER") : "ACCOUNT ACCESS"}
          </span>
        </header>
        <main>
          <div className="heading">
            <div>
              <div className="eyebrow">Account services</div>
              <h1>{title}</h1>
              <p>
                {onDashboard
                  ? "Review sign-in activity and requests requiring attention."
                  : onSettings
                    ? "Manage account access and the security policy."
                    : onAccount
                      ? "Manage your current session and view your account."
                      : registration
                        ? "Choose your username and a strong, unique password."
                        : "Enter your username and password to continue."}
              </p>
            </div>
            {onDashboard && (
              <span
                className={
                  "badge " + (connection.startsWith("Live") ? "good" : "bad")
                }
              >
                <Radio size={12} />
                {connection}
              </span>
            )}
          </div>
          {error && (
            <div className="alert bad" role="alert">
              {error}
            </div>
          )}
          {message && (
            <div className="alert good" role="status">
              {message}
            </div>
          )}
          {loading ? (
            <section className="panel" role="status">
              Loading your session…
            </section>
          ) : !session ? (
            <section className="panel">
              <h2>Connection unavailable</h2>
              <p>
                Your account and monitoring data are unavailable while the
                server is disconnected.
              </p>
              <button onClick={() => location.reload()}>
                Retry connection
              </button>
            </section>
          ) : (
            <>
              {!onAccount && !onDashboard && !onSettings && (
                <div className="auth-layout">
                  <section className="panel auth-card">
                    <div className="panel-icon">
                      {registration ? <UserPlus /> : <Shield />}
                    </div>
                    <h2>
                      {registration
                        ? "Register for portal access"
                        : adminSignIn
                          ? "Use your administrator account"
                          : "Account sign in"}
                    </h2>
                    {user ? (
                      <>
                        <p>
                          You are signed in as <strong>{user.username}</strong>.
                        </p>
                        <a
                          className="button"
                          href={isAdmin ? "/admin" : "/account"}
                        >
                          {isAdmin ? "Open monitoring" : "Open account"}
                        </a>
                      </>
                    ) : (
                      <>
                        <form onSubmit={authentication}>
                          <label htmlFor="username">Username</label>
                          <input
                            id="username"
                            name="username"
                            required
                            minLength={3}
                            maxLength={32}
                            pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]*"
                            autoComplete="username"
                            autoCapitalize="none"
                            spellCheck={false}
                          />
                          {registration && (
                            <small>
                              Use 3–32 characters: letters, digits, dot,
                              underscore, or hyphen. Usernames are
                              case-insensitive.
                            </small>
                          )}
                          <label htmlFor="password">Password</label>
                          <div className="password-input">
                            <input
                              id="password"
                              name="password"
                              required
                              minLength={registration ? 15 : 1}
                              maxLength={128}
                              type={visible ? "text" : "password"}
                              autoComplete={
                                registration
                                  ? "new-password"
                                  : "current-password"
                              }
                            />
                            <button
                              type="button"
                              className="icon-button"
                              aria-label={
                                visible ? "Hide password" : "Show password"
                              }
                              onClick={() => setVisible(!visible)}
                            >
                              {visible ? (
                                <EyeOff size={19} />
                              ) : (
                                <Eye size={19} />
                              )}
                            </button>
                          </div>
                          {registration && (
                            <small>
                              Use 15–128 characters. Spaces are allowed. Never
                              reuse a password from another service.
                            </small>
                          )}
                          <button
                            className="full"
                            disabled={busy || !csrf.current}
                          >
                            {busy
                              ? "Please wait…"
                              : registration
                                ? "Create account"
                                : "Sign in"}
                            {registration ? (
                              <UserPlus size={16} />
                            ) : (
                              <LogIn size={16} />
                            )}
                          </button>
                        </form>
                        {!adminSignIn && (
                          <p className="auth-link">
                            {registration
                              ? "Already registered?"
                              : "Need an account?"}{" "}
                            <a href={registration ? "/login" : "/register"}>
                              {registration ? "Sign in" : "Register"}
                            </a>
                          </p>
                        )}
                      </>
                    )}
                    {location.search.includes("expired=1") && (
                      <p role="status" className="caption">
                        Your session ended. Sign in again to continue.
                      </p>
                    )}
                  </section>
                  <section className="auth-help">
                    <h2>
                      {adminSignIn
                        ? "Administrator access"
                        : "Before you sign in"}
                    </h2>
                    <p>
                      {adminSignIn
                        ? "Monitoring and account administration are available only to authorized administrators."
                        : "Use the account you registered for this portal. Sign out when using a shared computer."}
                    </p>
                    <h3>
                      {adminSignIn
                        ? "Need administrator access?"
                        : "Do not have an account?"}
                    </h3>
                    <p>
                      {adminSignIn
                        ? "Ask your portal administrator to grant access. Creating a public account does not grant administrator permissions."
                        : "Registration creates a standard account. Your administrator manages additional permissions."}
                    </p>
                    {!adminSignIn && <a href="/register">Create an account</a>}
                    {adminSignIn && (
                      <details className="setup-help">
                        <summary>Set up the first administrator</summary>
                        <p>
                          The portal owner must run this command in PowerShell
                          from the Digital_Vault project folder, then return
                          here to sign in.
                        </p>
                        <code>npm run admin:setup</code>
                        <p>
                          The command asks for a username and a password
                          privately. No default administrator account is
                          provided.
                        </p>
                      </details>
                    )}
                    <hr />
                    <h3>Privacy and security</h3>
                    <p>
                      Sign-in attempts are recorded for account security.
                      Passwords are never included in these records.
                    </p>
                    <a href={adminSignIn ? "/login" : "/admin/login"}>
                      {adminSignIn
                        ? "Return to account sign in"
                        : "Administrator sign in"}
                    </a>
                  </section>
                </div>
              )}
              {onAccount && user && (
                <div className="grid">
                  <section className="panel">
                    <div className="panel-icon">
                      <UserRound />
                    </div>
                    <h2>Account details</h2>
                    <dl className="account-details">
                      <dt>Username</dt>
                      <dd>{user.username}</dd>
                      <dt>Account ID</dt>
                      <dd className="mono">{user.id}</dd>
                      <dt>Access</dt>
                      <dd>
                        <span className="badge">
                          {user.role === "admin"
                            ? "Administrator"
                            : "Standard user"}
                        </span>
                      </dd>
                      <dt>Registered</dt>
                      <dd>{date(user.createdAt)}</dd>
                    </dl>
                  </section>
                  <section className="panel">
                    <div className="panel-icon">
                      <Clock />
                    </div>
                    <h2>Current session</h2>
                    <span className="badge good">Authenticated</span>
                    <p>
                      Expires{" "}
                      {session.expiresAt ? date(session.expiresAt) : "soon"}.
                    </p>
                    <p className="caption">
                      Signing out invalidates this session immediately. A
                      session expires even when this page is left open.
                    </p>
                    {isAdmin && (
                      <a className="button" href="/admin">
                        Open security monitoring
                      </a>
                    )}
                  </section>
                </div>
              )}
              {onDashboard && isAdmin && (
                <>
                  <div className="stats">
                    {[
                      [
                        "Retained attempts",
                        summary
                          ? Object.values(summary.counts).reduce(
                              (sum, value) => sum + value,
                              0,
                            )
                          : undefined,
                      ],
                      ["Successful", summary?.counts.success || 0],
                      ["Failed", summary?.counts.failure || 0],
                      ["Blocked", summary?.counts.blocked || 0],
                    ].map(([label, value]) => (
                      <div className="stat" key={label}>
                        <span>{label}</span>
                        <strong>{value ?? "—"}</strong>
                        <small>Within retained activity</small>
                      </div>
                    ))}
                  </div>
                  {summary && summary.alerts.length > 0 && (
                    <section className="alert warning">
                      <strong>Repeated failed logins</strong>
                      <p>
                        These usernames have repeated failures within the last{" "}
                        {Math.round(summary.alertWindowSeconds / 60)} minutes.
                        Alerts report activity independently of blocking
                        controls.
                      </p>
                      {summary.alerts.map((alert) => (
                        <div className="alert-item" key={alert.username}>
                          <code>{alert.username}</code>
                          <span>
                            {alert.failures} failures · latest{" "}
                            {date(alert.lastAt)}
                          </span>
                        </div>
                      ))}
                    </section>
                  )}
                  <section className="panel">
                    <div className="feed-tools">
                      <h2>
                        Login activity{" "}
                        <span className="badge">
                          {audit?.retentionLimit || "…"} event retention
                        </span>
                      </h2>
                      <button
                        className="secondary"
                        disabled={auditLoading}
                        onClick={() => {
                          setPageNumber(1);
                          setSnapshot(undefined);
                          setRevision((v) => v + 1);
                        }}
                      >
                        Refresh newest
                      </button>
                    </div>
                    <form
                      className="filters"
                      onSubmit={(e) => {
                        e.preventDefault();
                        setSearch(draftSearch.trim());
                        setPageNumber(1);
                        setSnapshot(undefined);
                      }}
                    >
                      <label>
                        Outcome
                        <select
                          value={outcome}
                          onChange={(e) => {
                            setOutcome(e.target.value);
                            setPageNumber(1);
                            setSnapshot(undefined);
                          }}
                        >
                          {[
                            "all",
                            "success",
                            "failure",
                            "blocked",
                            "challenge",
                          ].map((o) => (
                            <option value={o} key={o}>
                              {o === "all" ? "All outcomes" : o}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Submitted username
                        <input
                          value={draftSearch}
                          onChange={(e) => setDraftSearch(e.target.value)}
                          maxLength={64}
                          placeholder="Filter by username"
                        />
                      </label>
                      <label>
                        Per page
                        <select
                          value={pageSize}
                          onChange={(e) => {
                            setPageSize(Number(e.target.value));
                            setPageNumber(1);
                            setSnapshot(undefined);
                          }}
                        >
                          {[10, 20, 50, 100].map((n) => (
                            <option value={n} key={n}>
                              {n}
                            </option>
                          ))}
                        </select>
                      </label>
                      <button className="secondary" disabled={auditLoading}>
                        Apply filter
                      </button>
                    </form>
                    {snapshot && (
                      <p className="caption">
                        Browsing a snapshot. Select Refresh newest to follow
                        incoming activity.
                      </p>
                    )}
                    {auditLoading && !audit ? (
                      <div className="empty" role="status">
                        Loading login activity…
                      </div>
                    ) : (
                      audit && (
                        <>
                          <div className="feed" aria-busy={auditLoading}>
                            {audit.events.map((event) => (
                              <details className="event" key={event.id}>
                                <summary>
                                  <span className="mono muted">
                                    {date(event.timestamp)}
                                  </span>
                                  <span>
                                    {event.username || "(not provided)"}
                                  </span>
                                  <span
                                    className={
                                      "badge " +
                                      (event.outcome === "success"
                                        ? "good"
                                        : event.outcome === "failure"
                                          ? "bad"
                                          : "warning")
                                    }
                                  >
                                    {event.status} · {event.outcome}
                                  </span>
                                  <span className="muted">
                                    {event.durationMs} ms
                                  </span>
                                </summary>
                                <div className="event-details">
                                  {[
                                    ["Request ID", event.id],
                                    [
                                      "Timestamp",
                                      new Date(event.timestamp).toISOString(),
                                    ],
                                    [
                                      "Username",
                                      event.username || "(not provided)",
                                    ],
                                    [
                                      "Account ID",
                                      event.accountId || "Not resolved",
                                    ],
                                    ["Client IP", event.ip],
                                    [
                                      "User-agent",
                                      event.userAgent || "Not provided",
                                    ],
                                    ["Password", event.password],
                                    ["Outcome", event.outcome],
                                    ["HTTP status", event.status],
                                    ["Duration", `${event.durationMs} ms`],
                                    [
                                      "Controls",
                                      event.controls.length
                                        ? event.controls.join(", ")
                                        : "None triggered",
                                    ],
                                  ].map(([label, value]) => (
                                    <div key={label}>
                                      <span className="muted">{label}</span>
                                      <code>{value}</code>
                                    </div>
                                  ))}
                                </div>
                              </details>
                            ))}
                            {audit.events.length === 0 && (
                              <div className="empty">
                                <Activity size={32} />
                                <h3>
                                  {audit.total === 0
                                    ? "No matching login attempts"
                                    : "No records on this page"}
                                </h3>
                                <p>
                                  Only submitted login requests from this portal
                                  appear here. Registration, page visits, and
                                  typing do not create login activity.
                                </p>
                              </div>
                            )}
                          </div>
                          <div className="pagination">
                            <span>
                              {audit.total} matching events · page {pageNumber}{" "}
                              of{" "}
                              {Math.max(1, Math.ceil(audit.total / pageSize))}
                            </span>
                            <div>
                              <button
                                className="secondary"
                                aria-label="Previous page"
                                disabled={pageNumber === 1 || auditLoading}
                                onClick={() => {
                                  if (pageNumber === 2) setSnapshot(undefined);
                                  setPageNumber((v) => v - 1);
                                }}
                              >
                                <ChevronLeft size={16} />
                              </button>
                              <button
                                className="secondary"
                                aria-label="Next page"
                                disabled={
                                  pageNumber * pageSize >= audit.total ||
                                  auditLoading
                                }
                                onClick={() => {
                                  if (!snapshot) setSnapshot(Date.now());
                                  setPageNumber((v) => v + 1);
                                }}
                              >
                                <ChevronRight size={16} />
                              </button>
                            </div>
                          </div>
                        </>
                      )
                    )}
                    <p className="caption">
                      {session.realtime === "poll"
                        ? "Passwords are never retained. Login activity is visible only to authorized administrators."
                        : "Passwords are never retained. Local requests normally display a loopback IP; forwarded client addresses are accepted only from explicitly configured proxies."}
                    </p>
                  </section>
                </>
              )}
              {onSettings && isAdmin && (
                <>
                  <section className="panel">
                    <h2>Security policy</h2>
                    <p>
                      Rate limits and temporary lockout are always enforced.
                      Changes apply to future requests; reducing retention
                      immediately removes the oldest excess login events.
                    </p>
                    {policy ? (
                      <form
                        onSubmit={async (e) => {
                          e.preventDefault();
                          await submit("/admin/settings", policy);
                        }}
                      >
                        <div className="policy-grid">
                          {(Object.keys(fieldLabels) as (keyof Policy)[]).map(
                            (key) => {
                              const [label, hint, min, max] = fieldLabels[key];
                              return (
                                <label key={key}>
                                  {label}
                                  <input
                                    type="number"
                                    required
                                    min={min}
                                    max={max}
                                    value={policy[key]}
                                    onChange={(e) =>
                                      setPolicy({
                                        ...policy,
                                        [key]: Number(e.target.value),
                                      })
                                    }
                                  />
                                  <small>{hint}</small>
                                </label>
                              );
                            },
                          )}
                        </div>
                        <button disabled={busy}>
                          {busy ? "Saving…" : "Save policy"}
                        </button>
                      </form>
                    ) : (
                      <p role="status">Loading policy…</p>
                    )}
                  </section>
                  <div className="grid">
                    <section className="panel">
                      <h2>
                        <UserPlus size={19} />
                        Create an account
                      </h2>
                      <p>
                        Create access for an authorized person. Public
                        registration always assigns standard access.
                      </p>
                      <form
                        onSubmit={async (e) => {
                          e.preventDefault();
                          const form = e.currentTarget;
                          const data = new FormData(form);
                          const payload = {
                            username: String(data.get("username")),
                            password: String(data.get("password")),
                            role: String(data.get("role")),
                          };
                          (
                            form.elements.namedItem(
                              "password",
                            ) as HTMLInputElement
                          ).value = "";
                          const result = await submit("/admin/users", payload);
                          if (result) {
                            form.reset();
                            setRefreshUsers((v) => v + 1);
                          }
                        }}
                      >
                        <label htmlFor="new-username">Username</label>
                        <input
                          id="new-username"
                          name="username"
                          required
                          minLength={3}
                          maxLength={32}
                          pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]*"
                          autoComplete="off"
                        />
                        <label htmlFor="new-password">Initial password</label>
                        <input
                          id="new-password"
                          name="password"
                          type="password"
                          required
                          minLength={15}
                          maxLength={128}
                          autoComplete="new-password"
                        />
                        <small>
                          15–128 characters. Share credentials only through your
                          approved private channel.
                        </small>
                        <label htmlFor="new-role">Access role</label>
                        <select id="new-role" name="role">
                          <option value="user">Standard user</option>
                          <option value="admin">Administrator</option>
                        </select>
                        <button className="full" disabled={busy}>
                          Create account
                        </button>
                      </form>
                    </section>
                    <section className="panel">
                      <h2>
                        <Users size={19} />
                        Registered accounts
                      </h2>
                      <p className="caption">
                        Most recent 100 accounts. Passwords and password hashes
                        are never displayed.
                      </p>
                      <div className="user-list">
                        {users.map((account) => (
                          <div className="user-row" key={account.id}>
                            <strong>{account.username}</strong>
                            <span className="badge">{account.role}</span>
                            <small>{date(account.createdAt)}</small>
                          </div>
                        ))}
                      </div>
                    </section>
                  </div>
                </>
              )}
            </>
          )}
        </main>
        <footer>
          Digital_Vault · Account services
          <span>Authorized access only</span>
        </footer>
      </div>
    </div>
  );
}
