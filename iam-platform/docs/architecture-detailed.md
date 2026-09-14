# IAM Platform Architecture

## 1. Scope and architectural intent

IAM Platform is a centralized V1 IAM/RBAC service implemented as one Python/FastAPI process backed by PostgreSQL. It is intentionally modular inside one deployment unit. The module boundaries separate responsibility and make later evolution possible without prematurely introducing microservices, queues, caches, or network contracts.

```text
                         FastAPI application
                                |
     +--------------------------+--------------------------+
     |                          |                          |
  API transport         IAM orchestration facade       Composition
  validation/routes       app/domain/iam.py            app/main.py
     |                          |                          |
     |             +------------+------------+             |
     |             |            |            |             |
     |        Identity   Authentication Authorization     |
     |        manager       services       policy         |
     |             |            |            |             |
     |             +------------+------------+             |
     |                          |                          |
     |                   Audit/Application                |
     |                   collaborators                    |
     |                          |                          |
     +--------------------------+--------------------------+
                                |
                    PostgreSQL connection adapter
                                |
                           PostgreSQL 16
```

The application is not an OAuth/OIDC provider yet. Those are later roadmap phases and are not represented by placeholder modules.

## 2. Component ownership

### API transport: `app/api`

Owns HTTP concerns:

- Route registration.
- Pydantic request models.
- UUID/path parsing.
- `X-Session-ID` header extraction.
- Conversion of expected `IamError` values into HTTP responses.
- OpenAPI/Swagger exposure.

The API layer does not own SQL, password hashing, role evaluation, or audit writes.

### Core: `app/core`

Owns cross-cutting primitives:

- Shared HTTP status enumeration.
- Framework-neutral `IamError` categories.
- Text and password validation.

The core package does not know about FastAPI routes or PostgreSQL.

### Orchestration facade: `app/domain/iam.py`

`IamService` is the stable V1 application boundary. It coordinates database operations and composes the domain collaborators. Existing routes, tests, bootstrap code, and integrations call this facade, which prevents the modularization from becoming a public API rewrite.

### Identity: `app/domain/identity.py`

`IdentityManager` owns:

- Users and lifecycle state.
- Groups.
- Roles.
- Permissions.
- User/group, user/role, and role/permission relationships.
- Effective permission lookup.

Groups are identity-only in V1. Membership does not grant permissions.

### Authentication: `app/domain/authentication.py`

Owns reusable authentication primitives:

- Argon2id password hashing with configurable parameters.
- Legacy bcrypt/scrypt verification for migration compatibility.
- Cryptographically random session IDs.
- Session ID SHA-256 digests.
- Session expiration timestamps.
- Reset-token generation.

The module does not persist data or decide HTTP responses.

### Authorization: `app/domain/authorization.py`

`AuthorizationPolicy` is the replaceable subject/resource/action boundary. V1 evaluates direct role permissions. Application target checks are performed before protected operations so an object ID cannot be used to bypass the protected-resource boundary.

### Audit: `app/domain/audit.py`

`AuditWriter` is the trusted write boundary for security events. Clients cannot call it directly. It receives actor, event, target, result, and safe metadata from server-side decisions.

### Applications: `app/domain/applications.py`

`ApplicationManager` owns protected application CRUD and deployment state transitions. Authorization remains outside the manager and occurs in the route/service control flow before the manager is called.

### Secret protection and TOTP: `app/domain/secrets.py`, `app/domain/totp.py`

`SecretProtector` provides authenticated reversible encryption for TOTP secrets. The current development backend uses Fernet and an externally supplied `TOTP_ENCRYPTION_KEY`. `TotpService` uses `pyotp` for RFC 6238 behavior and never owns key retrieval.

### Infrastructure: `app/infrastructure`

Owns:

- PostgreSQL connection creation.
- Schema initialization and verification.
- Development Docker integration.
- Runtime adapter behavior.

Infrastructure errors are converted to controlled application errors at the boundary; SQL values remain parameterized.

## 3. Dependency direction

```text
app.main
  -> app.application
  -> app.infrastructure

app.application
  -> app.api
  -> app.domain

app.api
  -> app.domain
  -> app.core

app.domain
  -> app.core
  -> app.domain.ports

app.infrastructure
  -> app.domain.ports
```

Domain modules do not import route functions. API modules do not construct SQL. The development launcher is not imported by domain code.

## 4. Composition and lifecycle

Production composition is `app.main:app`:

1. FastAPI application is constructed.
2. Startup ensures PostgreSQL schema exists and is complete.
3. Bootstrap configuration creates or connects the Administrator role/user.
4. Routes are mounted.
5. Requests execute against the shared service facade and connection factory.

The development launcher `python -m app.dev.server` loads `.env`, starts local PostgreSQL when configured, resets the development database once, enables demo-user seeding, and starts Uvicorn reload mode. Production startup does not seed demo accounts.

## 5. Persistence boundary

PostgreSQL is the final integrity authority. Constraints enforce:

- Unique usernames, emails, group names, role names, permission pairs, and application names.
- Foreign keys for all relationship tables.
- Cascading cleanup for user/role/group/session relationships.
- Session digests rather than raw bearer credentials.
- Encrypted TOTP secrets rather than plaintext secrets.

The project has no migration framework yet. Existing databases must be reset or migrated explicitly when schema changes are introduced.

## 6. Extension boundaries

The current interfaces are designed for later replacement:

- `SecretProtector` can move from Fernet to KMS/HSM/Vault.
- `AuthorizationPolicy` can evolve from RBAC to contextual decisions.
- `IamService` can later compose OAuth/token/OIDC services.
- `AuditWriter` can later publish to an immutable external sink.
- The PostgreSQL connection factory can remain the persistence adapter.

No future protocol is implemented merely to reserve a namespace.
