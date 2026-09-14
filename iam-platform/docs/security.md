# Security Model

## Request control flow

Every protected request follows:

```text
Request -> Authentication -> Authorization -> Operation -> Audit -> Response
```

Authentication resolves a server-side session to a user. Authorization is a centralized RBAC
check over the user's direct roles and each role's permissions. The protected operation is reached
only after that check succeeds. A denied decision is audited before returning `403`; audit logging
is evidence and never a substitute for prevention.

Structured HTTP bodies are validated by strict Pydantic request models before route logic runs.
Unknown fields, wrong types, oversized values, and malformed UUID path parameters are rejected with
controlled `422` responses. The service repeats business and security validation so direct callers
cannot bypass the HTTP boundary. PostgreSQL remains the final enforcement point for uniqueness,
foreign keys, required values, and relationship integrity.

## Authentication and sessions

Passwords must contain at least 12 characters and are hashed with configurable Argon2id. Existing
bcrypt and scrypt hashes can still be verified for account migration, but new password hashes never
fall back to a weaker algorithm. Passwords, hashes, sessions, and credentials are never returned or
logged. Login failures use a generic `401` response and increment a bounded
failure counter, locking the account after five failures for fifteen minutes. Inactive and locked
users cannot authenticate.

Sessions are opaque, cryptographically random bearer credentials. The raw identifier is returned
only at login, hashed with SHA-256 before database storage, and never stored or placed in URLs.
Requests hash the supplied `X-Session-ID` before lookup. Sessions have an eight-hour expiration,
can be revoked by logout, and are rejected after expiration, revocation, or account deactivation.
TLS is a deployment requirement because possession of the header value is sufficient to authenticate.
The V1 schema now names the stored value `sessions.id_hash`; an existing database must be migrated
or reset before deploying this change because the project does not yet include a migration framework.

Phase 1 authentication controls now include:

- `GET /auth/sessions` for the authenticated user's session metadata only; raw session identifiers
	and hashes are never returned.
- `POST /auth/sessions/revoke-all` to revoke every active session for the authenticated user.
- `POST /auth/password` to verify the current password, store a new Argon2id hash, revoke all
	existing sessions, and audit the transition.

Password changes deliberately invalidate all bearer sessions to prevent a previously issued
credential from remaining active after a credential change.

Password reset architecture is also in place:

- `POST /auth/password-reset/request` accepts an email and always returns the same generic response.
- The server generates a short-lived random token and stores only its SHA-256 digest.
- Delivery is intentionally an integration boundary; no email provider is coupled to V1 yet.
- `POST /auth/password-reset/complete` accepts the delivered token once, requires the password
	policy, marks the token used, revokes all existing sessions, and audits completion.
- Unknown, expired, reused, and malformed reset tokens fail without exposing account state.

### TOTP MFA

TOTP enrollment and verification use `pyotp` for RFC 6238 behavior. Generated secrets are
encrypted with authenticated Fernet encryption before storage in `totp_mfa.encrypted_secret`.
The `TOTP_ENCRYPTION_KEY` is external configuration: it is not stored in PostgreSQL, returned by
the API, or written to audit events. `SecretProtector` is the replaceable boundary for future KMS,
HSM, or Vault integration.

Enrollment is two-step: `/auth/mfa/totp/enroll` creates a disabled encrypted secret and returns a
provisioning URI; `/auth/mfa/totp/verify` must receive a valid code before MFA is enabled. Once
enabled, password-only login cannot create a session and `/auth/login` requires `totp_code`.
Disabling MFA requires the authenticated session, current password, and a valid current TOTP code.
MFA success and failure events are audited without codes or secrets.
TOTP verification accepts a deliberate `valid_window=1` clock-skew window, covering the adjacent
30-second time steps. To prevent unlimited guessing against the six-digit code space, five failed
attempts cause a 15-minute per-user MFA block; successful verification resets the counter.

## Authorization and privilege boundaries

Permissions are `(resource, action)` pairs. Groups do not grant permissions in V1. The bootstrap
Administrator role owns only `iam:manage`; application permissions can be assigned explicitly.
IAM administration requires both a valid session and `iam:manage`. Ordinary users cannot submit
privilege fields or forge audit events.

Authorization is implemented as a small in-process policy boundary. It evaluates the subject,
resource, and action, and target-aware application checks validate that the requested object exists
before the protected operation runs. V1 still uses global role permissions rather than ownership
or a full policy language; this keeps the interface replaceable without introducing a policy engine.

## Audit logging and sensitive data

Trusted server-side code records authentication outcomes, authorization decisions, privilege
changes, administrative operations, and state changes. Audit records include actor, event, target,
time, and result. Passwords, password hashes, session identifiers, tokens, and secrets are excluded.

Expected application errors are mapped by the API boundary to `400`, `401`, `403`, `404`, `409`,
and `429`. Unexpected exceptions are handled by the application error boundary and return only
`500 internal server error`; database messages, SQL, stack traces, credentials, and file paths are
not part of the response. Database uniqueness handling uses structured SQLSTATE information (with
the SQLite test adapter's structured exception type), not human-readable database messages.

All SQL values are parameterized. The only dynamic SQL is generated from service-owned field lists
for partial updates; those fields are selected from fixed method arguments, never client-supplied
column names. Authorization is evaluated explicitly per protected request and is not cached across
requests in V1.

## Threats and testing

The security test strategy covers generic login failures, inactive accounts, lockout, session
revocation and expiration, `401` versus `403`, IDOR, privilege escalation, relationship integrity,
parameterized SQL, operation-before-authorization ordering, and audit integrity. The lightweight
threat model is in `docs/threat-model.md`.

The automated CI security pipeline is documented in `docs/devsecops-security-pipeline.md`.

The executable security tests are documented by docstrings in `tests/unit/test_iam.py`:

| Test area | Purpose |
| --- | --- |
| Opaque sessions and secret exclusion | Prove successful login creates a server-side bearer session without exposing the password or session in audit output. |
| Generic failures and lockout | Prevent username enumeration and repeated password guessing. |
| Revocation, expiry, and inactive users | Prove old, revoked, expired, and deactivated credentials cannot authenticate. |
| Authorization and IDOR | Prove a valid session without the required permission cannot read a protected application. |
| Administrator role protection | Preserve the bootstrap privilege boundary against rename and delete operations. |
| Client privilege fields and audit write attempts | Prevent request payloads from granting roles or forging audit evidence. |
| SQL metacharacters | Prove login input is bound as data rather than executable SQL. |
| Malformed verifier and failure recovery | Prove corrupted password data fails closed and successful login clears stale lockout state. |
| PostgreSQL constraints and cascades | Prove duplicate identities/relationships, dangling references, and inherited privilege edges are controlled by database integrity. |
| Rejected mutation payloads | Prove unsupported fields and malformed UUIDs return validation errors without changing state. |

Run the offline security suite with `python -m pytest tests/unit/test_iam.py -q`. PostgreSQL
compatibility tests are opt-in and require the integration environment described in the README.
The latest complete local unit and PostgreSQL-backed suite contains 56 passing tests.

## Assumptions and limitations

V1 assumes TLS is provided by the deployment boundary and that PostgreSQL credentials are supplied
out of band. It does not implement MFA, OIDC, LDAP, WebAuthn, distributed rate limiting, key
rotation, or an immutable external audit sink. Production deployments need those controls and
secrets management before exposure to untrusted networks.
