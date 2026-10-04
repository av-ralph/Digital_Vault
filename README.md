# Digital_Vault — authentication and security monitoring

A local portal with real registered accounts, role-based access, SQLite persistence, and an administrator-only login audit dashboard. The database starts empty. No accounts, credentials, password lists, or login activity are seeded. The previous guessing/simulation features and educational challenge endpoints have been removed.

## Windows setup

Use Node.js 22.13 or newer (verified with 22.21). Node's built-in SQLite API is used; Node 22 prints an experimental-feature warning. No separate database installation is needed.

In PowerShell:

```powershell
cd C:\Users\user\Videos\LoginLab
npm --prefix LoginLab ci
Copy-Item LoginLab\.env.example LoginLab\.env
npm run db:init
npm run admin:setup
npm run dev
```

The initial administrator command prompts for a username and a hidden password, then asks you to confirm the password. Passwords are never placed in command arguments, printed, logged, or written as plaintext. It requires an interactive terminal and refuses to run again once an administrator exists. There are no default credentials. Use your own unique password of 15–128 characters. Usernames use 3–32 letters, digits, dots, underscores, or hyphens and are case-insensitive.

Open **http://127.0.0.1:5173**:

- `/login`: sign in.
- `/register`: public registration; all new accounts receive the `user` role.
- `/account`: authenticated account page.
- `/admin`: administrator-only login monitoring.
- `/admin/settings`: administrator-only security policy and account creation.

Existing bookmarked `/admin/login` and `/instructor` routes map to the new login and administrator monitoring views. The old account store was only an in-memory teaching fixture, so there are no genuine accounts to migrate. No competing identity provider was found in the repository.

The frontend binds to `127.0.0.1:5173` and proxies `/api` to the backend at `127.0.0.1:3001`. Both ports are strict and the backend always binds to loopback. Stop the services with Ctrl+C.

An authorized administrator can create additional users or administrators in Administration. Public registration rejects role fields and never grants administrator privileges. Duplicate registration receives the same generic accepted response as an available username; sign in after registration.

## Local production build

Stop development before starting the built application; both workflows use backend port 3001.

```powershell
npm run build
npm start
```

Open **http://127.0.0.1:3001**. The start command automatically uses that local origin unless you explicitly configure `TRUSTED_ORIGINS`. Both local startup modes are verified. No automatic publication or deployment is performed.

## Configuration and persistence

`LoginLab/.env.example` contains only non-secret configuration. Startup and administrator commands load `LoginLab/.env` automatically. Default settings:

| Setting | Default |
| --- | --- |
| API port | 3001 |
| SQLite database | `LoginLab/data/portal.sqlite` |
| Trusted browser origin (development) | `http://127.0.0.1:5173` |
| Trusted browser origin (built application) | `http://127.0.0.1:3001` |
| Trusted reverse proxies | none |
| Initial audit retention | 2,000 events |

`DATABASE_PATH` may point to another SQLite file. Relative paths resolve from the inner LoginLab project for the npm workflows. Keep the file and its WAL/SHM companions private and excluded from source control. Users, hashed credentials, hashed sessions, CSRF records, security counters, settings, and audit records persist across restarts. The schema initializes idempotently without inserting accounts or events. Expired sessions/CSRF records and obsolete rate buckets are periodically removed. Back up the database with a SQLite-aware backup or stop the services before copying the database and associated files.

`AUDIT_RETENTION_LIMIT` applies only on first database initialization. Later changes go through the protected administrator settings API and persist in SQLite. Shrinking retention deletes excess oldest audit rows immediately. Dashboard totals and alerts cover retained records, not an indefinite lifetime history.

`TRUSTED_ORIGINS` is an exact, comma-separated allowlist of origins; no wildcard CORS is enabled. HTTP origins are accepted only for loopback; other origins must use HTTPS. Backend Host values must match configured origins or the local API address. If changing PORT, also change the Vite proxy and development access-check target consistently. The documented standard ports are 5173 and 3001.

Client IP comes directly from the request socket by default. Forwarded headers are ignored. `TRUSTED_PROXY_IPS`, when explicitly configured, accepts only individually known proxy IP addresses; Express checks the trusted chain. Never set this to arbitrary or untrusted clients. Local requests normally display `127.0.0.1`, not a public visitor IP.

## Authentication and controls

- Each password has a cryptographically random salt and a 64-byte scrypt hash (N=16384, r=8, p=1), verified with a timing-safe comparison. No password contents enter audit records, API responses, browser storage, analytics, or console output. Inputs are cleared after submission. Unknown accounts still perform password hashing to reduce timing differences.
- Opaque random session tokens are stored only as SHA-256 fingerprints in SQLite. Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-only, and scoped to `/`. Expiry is absolute; logout invalidates the server session and session-bound CSRF token immediately. Reauthentication rotates the session. Local loopback Secure-cookie behavior is verified in the Chromium browser used for testing. For other browsers that reject Secure cookies on loopback HTTP, use trusted local HTTPS; do not weaken the cookie flags.
- Mutations require an explicitly trusted Origin plus a server-stored, random CSRF token. CSRF cookies are also Secure/HttpOnly/SameSite; the frontend obtains the token through the same-origin session endpoint and keeps it only in memory. Tokens rotate at login and are bound to the authenticated session. Pre-authentication tokens protect registration and login.
- Server-side authorization protects the account and administrator pages as well as every account/configuration/audit endpoint. In development, a Vite middleware verifies page access with the backend before serving protected React routes. The backend also enforces the roles when serving built pages. React alone never decides access.
- IP and account-name rate limits are always enforced. Defaults are 30 attempts per client and 10 per account name over 60 seconds. Rate blocks return HTTP 429 with Retry-After. Account-name limits apply equally to unknown names to avoid enumeration.
- Five consecutive incorrect passwords activate a five-minute lock. Correct authentication resets the counter. Expiry permits another attempt. Lockout applies to attempted account names, including unknown names, and login failures use the same generic response and HTTP 401 for wrong, unknown, and locked accounts. The administrator audit identifies the internal blocking control without revealing it to unauthenticated clients. Lock state is rechecked after asynchronous hashing to handle concurrent requests.
- Repeated failures generate administrator alerts independently of blocking: default three failures within 15 minutes. No alerts or activity are fabricated. Registration is additionally limited to five attempts per client per hour.
- JSON request bodies are limited to 4 KB; strict schemas reject unexpected fields. Audit usernames are safely rendered as React text, stripped of control characters, and capped at 64 characters. User-agent values are capped at 256. Security headers restrict framing and resource origins.

Policy thresholds, durations, session lifetime, and retention are configurable by authenticated administrators. Changes affect future requests and sessions; existing sessions keep their original expiry. Existing counters are preserved. The frontend never sends credentials to external services.

## Actual monitoring

Each submitted `POST /api/login` creates one record with timestamp, random request ID, submitted username, resolved account ID when available, socket/proxy client IP, user-agent, real outcome, actual HTTP status, request duration, and triggered controls. Passwords are always represented as `[REDACTED]`; no password field exists in the audit table. Rejected login requests (validation, CSRF, origin, or rate blocks) are also recorded with their real outcome. Page views, registration, typing, configuration changes, and account creation do not create login events.

The dashboard supports outcome and username filters, page size, pagination, retained totals, and an empty state. Page one follows live updates; older pages use a timestamp snapshot. Retention can remove old records during browsing, so refresh if a historical page becomes empty. Administrator SSE connections require a valid administrator session, send refresh notices for genuine audit changes, and are closed on logout or expiry. A reconnecting/disconnected indicator is visible.

Endpoints:

- Public: `GET /api/session`, `POST /api/register`, `POST /api/login` (POSTs require Origin and CSRF).
- Session: `POST /api/logout`, `GET /api/account`, `GET /api/access`.
- Administrator: `GET /api/admin/audit`, `/summary`, `/events`, `/settings`, `/users`; `POST /api/admin/settings` and `/users`.

The monitor recognizes success, failure, blocked, and challenge outcomes; no synthetic challenges or MFA events are generated. This revision does not implement MFA, email verification, password reset, external identity providers, or third-party interception.

## Verification

```powershell
npm test
npm run typecheck
npm run build
```

Automated tests create only isolated temporary SQLite fixtures and remove them afterward. They verify registration roles, salted hashing, one-time administrator setup, generic errors, password-free audit/database/API data, page/API authorization, session hashing/expiry/logout, CSRF/Origin/Host/size checks, IP/account rate limiting, lockout and expiry, alerts, retention/filtering/pagination, authorized SSE/logout, proxy trust, and database persistence. Tests do not seed the application's database.

Verification completed: all 19 automated tests pass; frontend, backend, and test TypeScript checks pass; the production build passes; database initialization and the hidden-password administrator command pass. Browser verification uses an isolated temporary database, separate from the application store. The UI is checked for registration/login/logout, protected account pages, administrator access, redacted live activity, policy saving, account creation, and mobile layout. Registration, login/logout, protected account access, standard-user rejection from administrator pages, administrator account creation and policy saving, redacted audit details, filters and empty states, and the mobile dashboard were verified. The mobile viewport had no horizontal overflow. SSE delivery, logout invalidation, and open-stream expiry are verified by the automated HTTP tests. A final attempt to reopen the existing browser error-page tab was blocked by its URL policy; use the documented local URL directly.

## Netlify deployment

The repository includes `netlify.toml`. Import it into Netlify from GitHub. The configured base directory is `LoginLab`, build command is `npm run build`, output is `dist`, and server functions are in `netlify/functions`. Node 22 is required. The internal folder keeps its original name to preserve existing local databases and Windows run commands; the application is Digital_Vault.

Netlify uses PostgreSQL via the official `@netlify/database` integration, with schema-only migrations in `LoginLab/netlify/database/migrations`. No accounts, passwords, audit events, or local database files are included in Git or deployments. Netlify should provision the database when it detects the integration; if needed, create it under the site's Data & Storage > Database. Migrations run before the deploy is published.

The hosted adapter uses the same account fields, scrypt parameters, roles, hashed opaque sessions, CSRF design, and validation as the local version. PostgreSQL transaction-scoped advisory locks serialize account lockout and rate counters across function instances. Every submitted login request is audited before the response completes; records never contain the submitted password. Host/origin validation uses platform site URLs and optional explicitly configured `TRUSTED_ORIGINS`. The client IP comes exclusively from Netlify's trusted function context. Protected account and administrator HTML pages are served through the function after server-side authorization.

Hosted monitoring uses authenticated polling every five seconds because serverless requests have execution limits. Local monitoring retains SSE. Accounts, sessions, guards, settings, and audit events persist in the hosted database across deploys. Configure retention through the administrator page. HTTP-only Secure SameSite=Strict cookies are used over Netlify HTTPS.

To create the first hosted administrator, obtain the production database connection string from Netlify and set `NETLIFY_DB_URL` privately in the local terminal environment or ignored `LoginLab/.env`. Never paste it into source, Git, logs, or chat. Then run:

```powershell
npm run cloud:admin
```

The command asks for a username and hidden password, and refuses once an administrator exists. The local administrator account does not automatically transfer to the hosted database. Set up the hosted administrator through this private command; additional users can register or be created by an administrator. Local SQLite remains available for offline development.

## Operational limits

Local mode uses SQLite and one Node process. Hosted mode uses Netlify Functions and PostgreSQL. The isolated PostgreSQL tests use an in-memory SQL emulator and do not prove network reliability or real PostgreSQL advisory-lock behavior; those require checks on the deployed database. The application does not implement MFA, email verification, password recovery, or a backup management UI. Protect the hosted database's credentials and use the provider's backup facilities. Netlify hosting and database usage may consume account credits.

Design references: [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP session management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), and [Node SQLite documentation](https://nodejs.org/download/release/latest-jod/docs/api/sqlite.html).


Administrator sign-in is available at `/admin/login`. Successful administrator authentication opens monitoring directly; standard accounts cannot access monitoring or administration. The interface uses a public-service inspired navy and white design with Digital_Vault branding. It does not represent a government agency.

If the username chosen during initial administrator setup already belongs to a registered account, setup promotes that existing account, securely replaces its password with the entered password, and invalidates its prior sessions. This is available only through the local one-time setup command before any administrator exists.
