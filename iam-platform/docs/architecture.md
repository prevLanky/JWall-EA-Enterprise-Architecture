# IAM V1 Architecture

## Components

`app/main.py` composes the production FastAPI application, PostgreSQL connection, schema startup,
and environment-driven bootstrap. `app/api.py` translates HTTP requests into authenticated service
calls. `app/iam.py` owns validation, authentication, session validation, centralized RBAC decisions,
protected state changes, and trusted audit writes. `app/database.py` owns PostgreSQL lifecycle
operations. `app/common` contains shared errors, statuses, and input validation.

## Data model

Users have direct many-to-many relationships with groups and roles. Roles have many-to-many
relationships with permissions. Groups are identity-only in V1. Sessions belong to users and carry
opaque identifiers, expiration, and revocation state. Applications are protected resources.
Audit events record security-relevant decisions and outcomes and reference the actor and target.
Foreign keys and unique constraints enforce relationship integrity.

## API structure

- `/auth`: login, logout, and session validation.
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

Passwords are stored only as established password-hash outputs. Login returns a cryptographically
random opaque session identifier. The server stores its user, creation time, expiration, and
revocation state. Logout revokes the session, and expired, revoked, inactive, or unknown sessions
return `401`.

## Bootstrap and lifecycle

Development PostgreSQL is supplied by Docker Compose. An explicit reset drops and recreates the
schema; it is never performed by ordinary reloads unless `IAM_RESET_DATABASE=true`. Startup creates
the Administrator role, `iam:manage`, and the administrator user from environment credentials.

## Extension points

Future group-to-role mappings, MFA, OIDC, distributed throttling, external immutable audit storage,
and migrations can be added behind the current service boundary. They are deliberately outside V1.
