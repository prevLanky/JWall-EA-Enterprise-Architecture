# IAM V1 Architecture

## Components

`app/main.py` composes the production FastAPI application, PostgreSQL connection, schema startup,
and environment-driven bootstrap. `app/api` validates strict request models and translates HTTP
requests into authenticated service calls. `app/domain/iam.py` remains the V1 orchestration
boundary, while `app/domain/authentication.py` owns password/session primitives and
`app/domain/authorization.py` owns the replaceable authorization policy boundary,
`app/domain/audit.py` owns trusted audit writes, and `app/domain/applications.py` owns protected
application operations. `app/domain/identity.py` owns users, groups, roles, permissions, and
relationship lifecycle operations. `app/domain/iam.py` is now the compatibility/orchestration
facade that composes these in-process collaborators. PostgreSQL lifecycle operations live in
`app/infrastructure/database.py`; shared errors, statuses, and input validation live in `app/core`.

## Data model

Users have direct many-to-many relationships with groups and roles. Roles have many-to-many
relationships with permissions. Groups are identity-only in V1. Sessions belong to users and carry
opaque identifiers, expiration, and revocation state. Applications are protected resources.
Audit events record security-relevant decisions and outcomes and reference the actor and target.
Foreign keys and unique constraints enforce relationship integrity.

## API structure

- `/auth`: login, logout, session validation/listing, password change, and session revocation.
- `/users`, `/groups`, `/roles`, `/permissions`: authenticated IAM administration.
- `/users/{id}/permissions`: effective permissions derived from roles.
- `/applications`: resource operations guarded by `application:*` permissions.

There is no client audit-write endpoint.

## Request flow and boundaries

```text
Client
  -> request validation
  -> session authentication
  -> user identity
  -> centralized RBAC authorization
  -> protected operation
  -> trusted audit event
  -> response
```

The client is untrusted and cannot choose the authenticated actor, authorization result, or audit
identity. FastAPI is the enforcement boundary. PostgreSQL is the persistence boundary and enforces
referential integrity. Authorization is evaluated before reading or mutating protected resources;
a denial is audited and returns `403`.

## Authentication and sessions

New passwords use configurable Argon2id hashes. Legacy bcrypt/scrypt hashes remain verifiable for
migration compatibility. Login returns a cryptographically random opaque session identifier; only
its SHA-256 digest is stored with the user, creation time, expiration, and revocation state. Logout
revokes the session, and expired, revoked, inactive, or unknown sessions return `401`.

TOTP MFA uses `pyotp` for RFC 6238 verification. Secrets are encrypted at rest through the
`SecretProtector` abstraction using an external Fernet key. Enrollment must be verified before MFA
is enabled, and login issues no authenticated session until a valid TOTP code is supplied for an
MFA-enabled user. The protector can later be replaced by KMS, HSM, or Vault integration.

## Bootstrap and lifecycle

Development PostgreSQL is supplied by Docker Compose. An explicit reset drops and recreates the
schema; it is never performed by ordinary reloads unless `IAM_RESET_DATABASE=true`. Startup creates
the Administrator role, `iam:manage`, and the administrator user from environment credentials.

## Extension points

Future group-to-role mappings, OIDC, distributed throttling, external immutable audit storage, and
migrations can be added behind the current service boundary. OAuth/OIDC and enterprise key-provider
integration remain deliberately outside this phase.
