# Digital_Vault — authentication and security monitoring

[Live portal](https://my-digital-vault.netlify.app/) | [GitHub repository](https://github.com/av-ralph/Digital_Vault)

An authentication portal with real registered accounts, role-based access, and an administrator-only login audit dashboard. Local development uses React, TypeScript, Express and SQLite; the hosted site uses Netlify Functions and PostgreSQL. The database starts empty. No accounts, credentials, password lists, or login activity are seeded. The previous guessing/simulation features and educational challenge endpoints have been removed.

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

Administrator sign-in is available at `/admin/login` and opens monitoring after authentication. The legacy `/instructor` route opens administrator monitoring.

The frontend binds to `127.0.0.1:5173` and proxies `/api` to the backend at `127.0.0.1:3001`. Both ports are strict and the backend always binds to loopback. Stop the services with Ctrl+C.

An authorized administrator can create additional users or administrators in Administration. Public registration rejects role fields and never grants administrator privileges. Duplicate registration receives the same generic accepted response as an available username; sign in after registration.

## Local production build

Stop development before starting the built application; both workflows use backend port 3001.

```powershell
npm run build
npm start
```

Open **http://127.0.0.1:3001**. The start command automatically uses that local origin unless you explicitly configure `TRUSTED_ORIGINS`. Both local startup modes are verified. These local commands do not publish the application. The connected Netlify site automatically builds and publishes changes pushed to the GitHub repository's main branch.

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

Latest verification: **all 30 automated tests pass**, TypeScript checks pass, and the production build succeeds. Tests use isolated SQLite fixtures, an in-memory PostgreSQL emulator, and mocked device-location providers. They do not seed accounts or positions into the application.

Additional location coverage verifies trusted IP metadata, optional consent, bounded coordinates, stale positions, permission denial, high-accuracy failure with standard-position fallback, cancellation, late callbacks, and watchdog timeouts.

Live checks confirmed administrator login/logout, genuine audit updates, protected monitoring, the IP-based OpenStreetMap display, published permission help, and successful login after a device-location timeout. The in-app browser did not return a real device position; successful acquisition there remains unverified. Automated tests validate position handling but cannot prove GPS availability on a user's device.

## Netlify deployment

The repository includes `netlify.toml`. Import it into Netlify from GitHub. The configured base directory is `LoginLab`, build command is `npm run build`, output is `dist`, and server functions are in `netlify/functions`. Node 22 is required. The internal folder keeps its original name to preserve existing local databases and Windows run commands; the application is Digital_Vault.

Netlify uses PostgreSQL via the official `@netlify/database` integration, with schema-only migrations in `LoginLab/netlify/database/migrations`. No accounts, passwords, audit events, or local database files are included in Git or deployments. Netlify should provision the database when it detects the integration; if needed, create it under the site's Data & Storage > Database. Migrations run before the deploy is published.

The hosted adapter uses the same account fields, scrypt parameters, roles, hashed opaque sessions, CSRF design, and validation as the local version. PostgreSQL transaction-scoped advisory locks serialize account lockout and rate counters across function instances. Every submitted login request is audited before the response completes; records never contain the submitted password. Host/origin validation uses platform site URLs and optional explicitly configured `TRUSTED_ORIGINS`. The client IP comes exclusively from Netlify's trusted function context. Protected account and administrator HTML pages are served through the function after server-side authorization.

Hosted monitoring uses authenticated polling every five seconds because serverless requests have execution limits. Local monitoring retains SSE. Accounts, sessions, guards, settings, and audit events persist in the hosted database across deploys. Configure retention through the administrator page. HTTP-only Secure SameSite=Strict cookies are used over Netlify HTTPS.

To create the first hosted administrator, obtain the production database connection string from Netlify and set `NETLIFY_DB_URL` privately in the local terminal environment or ignored `LoginLab/.env`. Never paste it into source, Git, logs, or chat. Then run:

```powershell
npm run cloud:admin
```

The command asks for a username and hidden password, and refuses once an administrator exists. The local administrator account does not automatically transfer to the hosted database. With explicit authorization, use npm run cloud:import-admin -- --username YOUR_USERNAME with the private NETLIFY_DB_URL configured. It transfers only the selected administrator identity and salted password hash, refuses when a hosted administrator exists, and transfers no sessions or audit history. Set up the hosted administrator through this private command; additional users can register or be created by an administrator. Local SQLite remains available for offline development.

## Operational limits

Local mode uses SQLite and one Node process. Hosted mode uses Netlify Functions and PostgreSQL. The isolated PostgreSQL tests use an in-memory SQL emulator and do not prove network reliability or real PostgreSQL advisory-lock behavior; those require checks on the deployed database. The application does not implement MFA, email verification, password recovery, or a backup management UI. Protect the hosted database's credentials and use the provider's backup facilities. Netlify hosting and database usage may consume account credits.

Design references: [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP session management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), and [Node SQLite documentation](https://nodejs.org/download/release/latest-jod/docs/api/sqlite.html).


Administrator sign-in is available at `/admin/login`. Successful administrator authentication opens monitoring directly; standard accounts cannot access monitoring or administration. The interface uses a public-service inspired navy and white design with Digital_Vault branding. It does not represent a government agency.

If the username chosen during initial administrator setup already belongs to a registered account, setup promotes that existing account, securely replaces its password with the entered password, and invalidates its prior sessions. This is available only through the local one-time setup command before any administrator exists.


## Login location and free maps

New hosted login attempts record the location supplied by [Netlify's included Functions geo API](https://docs.netlify.com/build/functions/api/): city, region, country and approximate coordinates when available. No API key or separate paid geolocation service is required. IP geolocation describes the network's estimated location, not an exact address or the device's GPS position; VPNs and mobile networks can produce different locations. Coordinates are rounded to two decimals. Local/private IPs show location unavailable, and existing audit history is not backfilled.

Only administrators can view location data, which expires with the associated audit record under the configured retention limit. Browsers cannot submit or override trusted IP-location metadata. Optional browser-reported device positions are stored and displayed separately. Selecting Show map loads an [OpenStreetMap embed](https://wiki.openstreetmap.org/wiki/Export), with attribution and a link to open the map. This sends the approximate map coordinates to OpenStreetMap; it never sends usernames, passwords, account IDs or audit records. The map uses no API key and depends on OpenStreetMap's public service availability. The dashboard works when the map cannot load.

## Optional device position at sign-in

Both account and administrator sign-in pages offer **Share device location**, off by default. Choose it before submitting a login and grant the browser's Location permission. **Cancel location request** stops waiting; **Remove location** excludes an acquired position from the login.

The free browser Geolocation API requests a fresh high-accuracy position with a 12-second timeout. Unavailable or timed-out results retry standard positioning with a 20-second timeout. Independent 18- and 22-second watchdogs bound waits if the browser never responds. Permission denial is not retried automatically. No movement tracking, background collection, page-load location requests, or browser-storage persistence occurs.

A device position is sent only with a submitted login attempt after the user chooses to share. Registration sends no position. Declining, cancelling or failing permission never prevents login; the available IP estimate remains. Device data follows the audit record's administrator-only access and retention policy.

The administrator's login details keep browser-reported coordinates and accuracy radius separate from trusted Netlify IP metadata. Device data is client supplied and can be spoofed; it is not used for authentication, authorization or evidence of an exact physical location. The browser may use GPS, Wi-Fi or other methods and precision is not guaranteed. Server validation requires explicit consent, finite bounded coordinates and nonnegative accuracy, and ignores positions older than five minutes. Coordinates are retained to six decimal places with the audit's existing retention policy. Existing records remain intact.

Device maps load only after Show device map is clicked. A notice explains that this shares the device coordinates with OpenStreetMap. No additional API key or paid service is required. Geolocation requires HTTPS (or a secure local loopback context) and device/browser support. See [browser location documentation](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation/getCurrentPosition).

### Location troubleshooting

| Message or situation | What to do |
| --- | --- |
| Permission blocked or declined | Allow **Location** in this site's browser permissions, reload, then retry. The website cannot reset a denied permission. |
| Position unavailable or both attempts timed out | Enable device location services and browser access. On Windows, check Settings > Privacy & security > Location, including access for desktop apps. |
| Embedded browser cannot return a position | Open [Digital_Vault](https://my-digital-vault.netlify.app/login) in Chrome, Edge or a phone browser with location permission enabled. |
| No device position shared | Sign-in still works; monitoring displays the available IP estimate. |

The button's **Location not working?** section provides these instructions and opens automatically after permission denial. The dashboard labels device positions as browser-reported and displays their reported accuracy radius. An IP address cannot supply an exact physical address, and a device position is not guaranteed to be exact.
