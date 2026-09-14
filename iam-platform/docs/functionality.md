# IAM Platform Functionality

## 1. Capability overview

The current system provides centralized identity, authentication, authorization, protected application operations, and audit evidence.

| Capability | Status | Primary surface |
| --- | --- | --- |
| User lifecycle | Implemented | `/users` |
| Groups and membership | Implemented; groups are identity-only | `/groups`, `/users/{id}/groups` |
| Roles and permissions | Implemented | `/roles`, `/permissions` |
| Effective permissions | Implemented | `/users/{id}/permissions` |
| Password authentication | Implemented | `/auth/login` |
| Server-side sessions | Implemented | `/auth/session`, `/auth/logout` |
| Password change | Implemented | `/auth/password` |
| Password reset architecture | Implemented; delivery integration deferred | `/auth/password-reset/*` |
| TOTP MFA | Implemented | `/auth/mfa/*`, login `totp_code` |
| Protected applications | Implemented | `/applications` |
| Audit read access | Implemented for administrators | `/audit` |
| OAuth/OIDC/JWT/SCIM/federation | Deferred | No routes yet |

## 2. Authentication endpoints

### `POST /auth/login`

Request:

```json
{
  "username": "admin",
  "password": "LocalAdminPassword",
  "totp_code": "123456"
}
```

`totp_code` is optional for users without enabled MFA and required for enabled MFA users. A successful response contains an opaque session ID, user ID, and expiration time. The raw session ID is returned only at login and is never stored raw in PostgreSQL.

Responses:

- `200`: session issued.
- `401`: generic authentication/MFA failure.
- `429`: password or TOTP throttling.
- `422`: malformed request body.

### `POST /auth/logout`

Requires `X-Session-ID`. Revokes the current session and writes logout/revocation audit events.

### `GET /auth/session`

Requires `X-Session-ID`. Returns only the authenticated user ID.

### `GET /auth/sessions`

Requires `X-Session-ID`. Returns session metadata only: created time, expiration, and revoked state. It never returns session IDs or hashes.

### `POST /auth/sessions/revoke-all`

Requires `X-Session-ID`. Revokes every active session belonging to the authenticated user.

### `POST /auth/password`

Requires `X-Session-ID` and the current password. Stores a new Argon2id hash and revokes all existing sessions.

### Password reset endpoints

`POST /auth/password-reset/request` accepts an email and returns the same generic response whether the account exists. A short-lived random token is generated internally and only its hash is stored. Email/SMS delivery is not implemented yet.

`POST /auth/password-reset/complete` consumes a valid single-use token and new password, then revokes sessions.

## 3. TOTP MFA endpoints

### `POST /auth/mfa/totp/enroll`

Requires an existing authenticated session and current password. Returns a provisioning URI compatible with authenticator applications. Enrollment is not enabled until verification succeeds.

### `POST /auth/mfa/totp/verify`

Requires the authenticated session and a six-digit code. Enables MFA only after valid verification.

### `GET /auth/mfa`

Requires an authenticated session. Returns `{ "enabled": true|false }`; no secret material is returned.

### `DELETE /auth/mfa/totp`

Requires the authenticated session, current password, and current TOTP code. This prevents a stolen or weakly authenticated request from disabling MFA.

## 4. Identity administration

All IAM administration requires:

```text
valid session + iam:manage permission
```

Available resources:

- Users: create, list, retrieve, update, delete.
- Groups: create, list, retrieve, update, delete.
- Roles: create, list, retrieve, update, delete.
- Permissions: create, list, retrieve, delete.
- Relationships: user/group, user/role, role/permission assignment/removal.
- Audit: administrator-only read access.

Request bodies use strict Pydantic models. Unknown fields are rejected rather than silently ignored.

## 5. Protected application functionality

Applications require resource-specific permissions:

| Operation | Permission |
| --- | --- |
| Create/list/read | `application:create` or `application:read` |
| Update | `application:update` |
| Delete | `application:delete` |
| Deploy | `application:deploy` |

A target application ID is checked before the manager performs the operation. Missing targets produce controlled `404`; authenticated users without permission receive `403`.

## 6. Local demonstration accounts

The development launcher seeds:

- `demo-reader`: read only.
- `demo-operator`: create/read/update/deploy.
- `demo-developer`: full application permissions.
- `demo-auditor`: read only.
- `demo-publisher`: create/read/deploy.

Groups such as `Platform Observers`, `Release Operators`, and `Engineering` demonstrate identity relationships only. They do not grant permissions in V1.

## 7. Browser and API clients

`/login` is a lightweight browser helper. It calls the same API endpoints as other clients and stores the raw session only in browser `sessionStorage` under `iam-session-id`. The API itself uses the `X-Session-ID` header, not cookies. Swagger remains available at `/docs` for endpoint exploration.

## 8. Expected authorization outcomes

| Authentication | Authorization | Result |
| --- | --- | --- |
| Missing/invalid session | Not evaluated | `401` |
| Valid session | Required permission missing | `403` |
| Valid session | Required permission present | Operation result |
| Valid session | Target object missing | `404` before operation |
| Malformed request | Not evaluated | `422` |

## 9. Browser admin portal

`GET /admin` serves a lightweight same-origin administration portal. It is a browser shell rather
than a second authorization system:

- `/login` creates the existing session and stores the raw bearer value in browser `sessionStorage`.
- `/admin` sends that value as `X-Session-ID` for each data request.
- Users, groups, roles, permissions, applications, and audit panels call the existing protected
  API endpoints.
- Application creation is exposed as a small portal action; update/delete/relationship operations
  remain available through the API/Swagger surface until their portal controls are added.
- A normal user can open the page, but receives the API's `401`/`403` responses for protected data.
- No password, session hash, TOTP secret, or authorization decision is duplicated in the page.

The distinction is deliberate: presentation access to `/admin` is separate from authorization to
perform operations. The API remains authoritative even if a user manually calls an endpoint or
modifies the browser UI.
