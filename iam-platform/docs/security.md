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

## Authentication and sessions

Passwords are hashed with bcrypt when installed, with a scrypt fallback in the service test
adapter. Passwords, hashes, sessions, and credentials are never returned or logged. Login failures
use a generic `401` response and increment a bounded failure counter, locking the account after five
failures for fifteen minutes. Inactive and locked users cannot authenticate.

Sessions are opaque, cryptographically random server-side identifiers. They have an eight-hour
expiration, can be revoked by logout, and are rejected after expiration, revocation, or account
deactivation. The API accepts the identifier in `X-Session-ID`.

## Authorization and privilege boundaries

Permissions are `(resource, action)` pairs. Groups do not grant permissions in V1. The bootstrap
Administrator role owns only `iam:manage`; application permissions can be assigned explicitly.
IAM administration requires both a valid session and `iam:manage`. Ordinary users cannot submit
privilege fields or forge audit events.

## Audit logging and sensitive data

Trusted server-side code records authentication outcomes, authorization decisions, privilege
changes, administrative operations, and state changes. Audit records include actor, event, target,
time, and result. Passwords, password hashes, session identifiers, tokens, and secrets are excluded.

## Threats and testing

The security test strategy covers generic login failures, inactive accounts, lockout, session
revocation and expiration, `401` versus `403`, IDOR, privilege escalation, relationship integrity,
parameterized SQL, operation-before-authorization ordering, and audit integrity. The lightweight
threat model is in `docs/threat-model.md`.

## Assumptions and limitations

V1 assumes TLS is provided by the deployment boundary and that PostgreSQL credentials are supplied
out of band. It does not implement MFA, OIDC, LDAP, WebAuthn, distributed rate limiting, key
rotation, or an immutable external audit sink. Production deployments need those controls and
secrets management before exposure to untrusted networks.
