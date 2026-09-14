# IAM Platform

This project is a small IAM platform demonstrating authentication, server-side sessions, RBAC,
protected resources, and security audit flow.

## Run locally

PostgreSQL must be running and the target database must exist. Set `DATABASE_URL` when the
default connection (`postgresql://postgres:postgres@localhost:5432/iam`) is not suitable.

For local development, the VS Code run/debug configurations set `IAM_AUTO_START_POSTGRES=true`.
When Docker Desktop is installed, the application will create or start a PostgreSQL 16 container
named `iam-postgres` automatically. This is a development convenience only; production should
manage PostgreSQL outside the application.

Use the development launcher for the intended lifecycle. It resets the database once when you
manually start the program, then enables Uvicorn reloads without resetting data when files change:

```bash
python -m app.dev.server
```

At startup the application connects to PostgreSQL with a five-second timeout, creates the local
development schema, verifies all expected tables and columns, and bootstraps the Administrator role
from environment-provided credentials. Set `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD`,
and `BOOTSTRAP_ADMIN_EMAIL` before starting. The application fails closed when any bootstrap value
is missing; it never starts a fresh database without an administrator.

```powershell
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

The FastAPI, Starlette, httpx, and AnyIO versions are intentionally pinned together because they
share the test-client compatibility boundary. The test configuration filters the known upstream
test-client deprecation warning; application warnings and errors remain visible.

The API is available at `http://127.0.0.1:8002`. The schema is initialized at startup using
the SQL in `docs/schema.sql`; there is deliberately no migration framework yet. Docker Compose
provides PostgreSQL only:

```powershell
Copy-Item .env.example .env
# Edit .env and replace every CHANGE_ME value locally.
docker compose up -d postgres
python -m app.dev.server
```

`.env` is ignored by Git. Store real database and administrator values only in that local file or
in your terminal environment. Do not put real values in `.env.example`, source files, Docker
Compose files, tests, or documentation.

The direct command `python -u app/main.py` also uses this same one-time-reset and non-destructive
reload behavior. Use `uvicorn app.main:app` directly only when you do not want an automatic reset.
Keep this terminal running while calling the endpoints. Open `http://127.0.0.1:8002/docs` for
the interactive Swagger client, or check `http://127.0.0.1:8002/health` first. In Swagger, call
`POST /auth/login`, copy the returned `session_id`, select **Authorize**, and paste it into the
`X-Session-ID` field. Protected endpoints can then be called from the browser.

Authentication management endpoints include `GET /auth/sessions`, `POST /auth/password`, and
`POST /auth/sessions/revoke-all`. Password changes and revoke-all operations invalidate existing
sessions; session listing returns metadata only and never returns session credentials.

Password reset endpoints are available as an integration-ready flow:
`POST /auth/password-reset/request` and `POST /auth/password-reset/complete`. The request endpoint
does not reveal whether an email exists. V1 stores only a hash of the short-lived reset token;
connecting token delivery to email or another provider remains outside the core service.

### TOTP MFA

Generate a local encryption key before using MFA:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the generated value in `.env` as `TOTP_ENCRYPTION_KEY`. Never commit it or store it in the
database. Use `POST /auth/mfa/totp/enroll` with the current password, scan the returned provisioning URI, and call
`POST /auth/mfa/totp/verify` with the six-digit code. Once enabled, include `totp_code` in
`POST /auth/login`. Production should replace the development key source with KMS, HSM, Vault, or
equivalent key management.

Login with `POST /auth/login`. Send the returned opaque `session_id` in the `X-Session-ID`
header for protected requests. `401` means the session is missing or invalid; `403` means the
authenticated user lacks the required permission.

New passwords use configurable Argon2id hashing. Legacy bcrypt/scrypt hashes remain verifiable so
existing local accounts can migrate without an authentication outage; new password creation never
silently falls back to a weaker algorithm.

For quick browser testing, open [http://127.0.0.1:8002/login](http://127.0.0.1:8002/login).
The page calls the same login, session, and logout endpoints as the API, keeps the session only in
browser `sessionStorage`, and shows demo-account buttons during development. It does not replace
the API authentication flow or store passwords on the server.

After signing in, open [http://127.0.0.1:8002/admin](http://127.0.0.1:8002/admin) for the small
administration portal. It displays users, groups, roles, permissions, applications, and audit
events, and includes an application-create action. All portal data and operations are still
authorized by the existing API; an administrator session is required for the IAM panels.

### Local demo users

The development launcher sets `IAM_SEED_DEMO_USERS=true` internally and creates these repeatable
local-only accounts after bootstrapping the administrator. They are not created by normal
production startup:

| Username | Password | Role | Application permissions |
| --- | --- | --- | --- |
| `demo-reader` | `DemoReaderPassword1` | Demo Reader | `read` |
| `demo-operator` | `DemoOperatorPassword1` | Demo Operator | `create`, `read`, `update`, `deploy` |
| `demo-developer` | `DemoDeveloperPassword1` | Demo Developer | `create`, `read`, `update`, `delete`, `deploy` |
| `demo-auditor` | `DemoAuditorPassword1` | Demo Auditor | `read` |
| `demo-publisher` | `DemoPublisherPassword1` | Demo Publisher | `create`, `read`, `deploy` |

Use these accounts to verify `403` authorization behavior against the protected application
endpoints. These are intentionally predictable dummy credentials for local development only and
must never be reused outside the local database.

The development seed also creates these identity-only groups:

| Group | Members |
| --- | --- |
| `Platform Observers` | `demo-reader`, `demo-auditor` |
| `Release Operators` | `demo-operator`, `demo-publisher` |
| `Engineering` | `demo-operator`, `demo-developer`, `demo-publisher` |

Groups do not grant permissions in V1. Effective permissions come from direct role assignments;
the groups are present so relationship and identity-management endpoints can be exercised.

To mount IAM into another FastAPI application, construct an `IamService` with the host's
connection factory and include `create_router(service)`. For a standalone application with a
custom startup action, use `create_app(service, startup_action)` from `app.application`.

Shared status codes and error helpers are available from `app.core`; feature code should use
those helpers instead of defining numeric HTTP statuses or framework-specific exceptions.

## Current scope

The API supports users, groups, roles, permissions, relationships, effective permissions,
username/password authentication, server-side sessions, protected applications, bootstrap
administration, and trusted audit events. Groups are identity data only and do not grant
permissions in V1.

## Tests

```powershell
pytest
```

The tests use a test-only in-memory SQL connection double so they validate IAM behavior without
requiring a PostgreSQL server. Production code uses PostgreSQL through `psycopg`.

## Documentation

The detailed documentation index is [docs/documentation-index.md](docs/documentation-index.md).
It links the architecture, functionality, security mechanisms, data flows, control flows and
interfaces, threat model, database schema, and DevSecOps pipeline reference.

## CI security pipeline

Pull requests and pushes to `main` or `dev` that change `iam-platform/` run the open-source security
pipeline documented in `docs/devsecops-security-pipeline.md`. It runs Semgrep, Gitleaks, Trivy,
Pytest, Syft, and an OWASP ZAP baseline scan against a temporary local API. Reports are uploaded
as workflow artifacts; confirmed secrets, high/critical findings, failed tests, and incomplete
scans block the security gate. Other systems in the monorepo can have their own path-scoped
workflow without changing this project.



# Docker setup
In powershell:
wsl --install
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
restart pc
bcdedit /enum {current}
if "OFF" do:
bcdedit /set hypervisorlaunchtype auto
wsl --status

troubleshoot:
Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
Get-Service vmcompute


# Start Iam

cd C:\repositories\enterprise_architect\iam-platform
docker compose down -v
docker compose up -d postgres
python -u app/main.py

python -u "C:\repositories\enterprise_architect\iam-platform\app\main.py"

Oneliner:
cd C:\repositories\enterprise_architect\iam-platform; $env:POSTGRES_USER="postgres"; $env:POSTGRES_PASSWORD="LocalPostgresPassword"; $env:POSTGRES_DB="iam"; $env:DATABASE_URL="postgresql://postgres:LocalPostgresPassword@localhost:5432/iam"; $env:BOOTSTRAP_ADMIN_USERNAME="admin"; $env:BOOTSTRAP_ADMIN_PASSWORD="LocalAdminPassword"; $env:BOOTSTRAP_ADMIN_EMAIL="admin@example.test"; $env:IAM_PORT="8002"; docker compose down -v; docker compose up -d --wait postgres; python -u app/main.py



# Auth
Start the server, then open:
http://127.0.0.1:8002/docs
In Swagger:
Call POST /auth/login.
Enter:
{
  "username": "admin",
  "password": "admin"
}
Copy the returned session_id.
Click Authorize at the top right.
Paste the session ID into the X-Session-ID field.
Click Authorize.
Call protected endpoints such as: