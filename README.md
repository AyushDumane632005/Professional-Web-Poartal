# VisionON Safety Intelligence

VisionON is a role-based safety portal with an Express/PostgreSQL backend. The sign-in page uses the database-backed API. There is no demo or quick-login path.

## Live roles

- **Employee:** own assigned tasks, incident records linked to their user, and task acknowledgements.
- **Safety Manager:** incidents, cameras, tasks, reports, review, and publication for granted sites.
- **VP / HQ:** published report summaries and organization site list. The API omits employee identity from executive report projections.
- **Platform Admin:** accounts, role/site grants, sign-in/access audit metadata. Incident and report endpoints deny this role.

The API enforces role and site checks independently of the UI. Sign-in uses an HTTP-only session cookie, password hashes, login rate limits, and same-origin checks on authenticated writes. The included dashboard charts, compliance rates, camera video, and AI model inference are not fabricated in live mode: compliance and trends show as unavailable until their data sources are connected.

## Start a local full-stack instance

Requires Docker Desktop with Compose. From PowerShell:

```powershell
Copy-Item .env.example .env
# Edit .env and replace every placeholder with unique random values, including ADMIN_EMAIL and ADMIN_PASSWORD.
docker compose up --build
```

Open `http://localhost:3000`. The database schema and first platform-admin account are initialized automatically. The first admin email and password come from `.env`. After login, create user accounts and site grants from **Access control**. The initial administrator credentials are configured in `.env`. New accounts receive unique temporary passwords shown once after creation and must change them at first sign-in.

`POSTGRES_PASSWORD` should be a unique value of at least 24 characters. Compose passes it separately from the database URL, so punctuation is supported. Set distinct random secrets for `JWT_SECRET` (32+ characters), `ADMIN_PASSWORD` (16+ characters), and `DETECTION_API_TOKEN` (32+ characters). Do not commit `.env`. Local HTTP uses `COOKIE_SECURE=false`; set `COOKIE_SECURE=true` behind HTTPS before exposing the site. If a trusted reverse proxy is in front, configure `TRUST_PROXY_HOPS` to the exact number of trusted proxies.

Health endpoint: `/api/healthz`. The API and static site share one origin. Postgres is not published to the host by Compose. The application port is bound to loopback for a local reverse proxy; change the binding only when the network and HTTPS termination are configured.

## PPE model integration

The model or trusted camera gateway can submit detections to `POST /api/detections` with `Authorization: Bearer <DETECTION_API_TOKEN>` and JSON like:

```json
{
  "cameraId": 1,
  "eventType": "hard_hat_missing",
  "severity": "high",
  "confidence": 0.94,
  "occurredAt": "2026-10-10T10:42:00Z",
  "personUserId": 27,
  "evidenceObjectKey": "private/site-1/camera-1/event-123.jpg"
}
```

The API records the event as pending human review. Camera rows and encrypted evidence storage must be provisioned separately. Do not send video or image bytes to this API; use private object storage with limited access and a retention policy. `personUserId` is optional and should only be supplied when a trustworthy, approved identity-matching workflow exists.

## Deployment boundary

The repo now includes the login-to-API flow, database-backed role pages, account/site management, incident/report/task operations, and model detection ingestion. Public launch still needs a hosting account, domain and HTTPS, production database backup/restore, secret provisioning, camera/object-storage setup, and your real PPE model endpoint/token. SSO and password reset email are not configured. Live camera streaming and analytics time-series are not implemented. Use a staging deployment and verify the role matrix before publishing an operational service.

## Production deployment and rollback

The supported deployment unit is Docker Compose on a Linux VM, with a host-managed HTTPS reverse proxy in front of the app. Keep the app bound to loopback (`127.0.0.1:3000`) and do not publish the PostgreSQL port. Use a managed secret store or a root-readable `.env` file, with separate random values for every environment. In production set `COOKIE_SECURE=true`, `TRUST_PROXY_HOPS=1` when exactly one trusted proxy is used, and `PGSSLMODE=require` when the database connection requires TLS. The app refuses to start in `NODE_ENV=production` without secure cookies.

Before deployment, provision the VM, Docker Engine/Compose, domain, TLS certificate, firewall rules, database backup storage, and secret values. Set `NODE_ENV=production` and `COOKIE_SECURE=true` in the production environment. From the repository directory:

```sh
cp .env.example .env
chmod 600 .env
# Edit .env using the secret store values. Set COOKIE_SECURE=true and TRUST_PROXY_HOPS=1.
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 app db
curl --fail http://127.0.0.1:3000/api/healthz
```

Install the reverse proxy and certificate for the real hostname before routing public traffic. Verify that HTTPS works, HTTP redirects to HTTPS, and the browser receives the `Secure`, `HttpOnly`, `SameSite=Strict` session cookie. Back up PostgreSQL before each release with `docker compose exec -T db pg_dump -U visionon visionon > visionon-pre-release.sql`. Keep backups encrypted and outside the Compose volume.

Schema initialization and additive updates run in `setup.js` each time the app container starts. For rollback, stop traffic, preserve a fresh database dump, deploy the previously pinned application image, and restore the matching pre-release database backup if the new schema or application changed stored data. Do not delete the named `visionon-data` volume as a rollback method. Validate restore procedures in staging before production; this repository does not automate backup retention or point-in-time recovery.

Set up the first admin only on a fresh database. Rotating `POSTGRES_PASSWORD` requires coordinated PostgreSQL role and `DATABASE_URL` updates; changing only `.env` does not change the password in an already initialized database volume. Rotate `JWT_SECRET` to invalidate all sessions. Rotate `ADMIN_PASSWORD` through a controlled account recovery procedure; the application has no password reset flow. Treat all existing `.env` credentials as needing rotation before production because this audit could not establish their exposure history or verify Git tracking status.

## Verification commands

Run `npm test` for the local role-policy and session-revocation unit tests, and `npm audit --omit=dev` to check installed production dependencies against the registry. The role/site endpoint matrix still requires PostgreSQL-backed integration tests and should be run against an isolated staging database before release.
