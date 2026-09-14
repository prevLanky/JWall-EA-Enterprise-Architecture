# Control Flows and Interfaces

## 1. HTTP error contract

| Condition | Boundary | Response |
| --- | --- | --- |
| Missing/invalid session | `authenticate` | `401 authentication required` |
| Invalid password/TOTP | authentication service | Generic `401` |
| TOTP/password attempt block | authentication throttle | `429` |
| Missing permission | authorization policy | `403` |
| Missing target object | target-aware authorization/resource manager | `404` |
| Duplicate constrained value | database/service conflict mapping | `409` |
| Invalid body/path | Pydantic/FastAPI validation | `422` |
| Unexpected exception | global FastAPI handler | `500 internal server error` |

The global handler does not expose exception messages, SQL, stack traces, or filesystem paths.

## 2. API interfaces

### Browser admin interface

```text
GET /login -> browser login helper
GET /admin -> admin portal shell
```

The portal has no privileged server-side channel. It reads the session from browser
`sessionStorage`, sends `X-Session-ID`, and renders the API response. The server therefore remains
the authority for every panel and action. Opening `/admin` alone does not authenticate or grant
access.

### Session interface

```text
X-Session-ID: <raw bearer session ID>
```

The server hashes the value before lookup. The API does not use cookies, JWTs, or URL session identifiers in V1.

### Login interface

```json
POST /auth/login
{
  "username": "string",
  "password": "string",
  "totp_code": "optional six digits"
}
```

Success returns `session_id`, `user_id`, and `expires_at`. A raw session ID is a secret and should be retained only by the client session context.

### MFA interfaces

```text
POST /auth/mfa/totp/enroll
    session header + current_password
    -> provisioning_uri

POST /auth/mfa/totp/verify
    session header + code
    -> 204 and enabled state

GET /auth/mfa
    session header
    -> { enabled: boolean }

DELETE /auth/mfa/totp
    session header + current_password + code
    -> 204
```

No MFA endpoint accepts a target user ID. The authenticated subject is derived from the session.

## 3. Domain interfaces

### `IamService`

Stable V1 facade used by API routes, bootstrap, tests, and integration code. It composes:

- `IdentityManager`
- `Authentication` primitives
- `AuthorizationPolicy`
- `AuditWriter`
- `ApplicationManager`
- `TotpService`
- `SecretProtector`

### `SecretProtector`

```python
class SecretProtector:
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...
```

The current implementation is Fernet with a development environment key. A KMS/HSM/Vault adapter can replace it without changing TOTP service logic.

### `AuthorizationPolicy`

```text
authorize(subject_id, resource, action, target_id=None) -> allow or controlled denial
```

V1 uses direct role permissions. Target-aware application checks validate object existence before the operation. Ownership/contextual PBAC is deferred.

### `AuditWriter`

```text
record(actor, event_type, target_type, target_id, result, safe_metadata)
```

Only trusted service code calls this interface.

## 4. Protected endpoint control flow

Every protected handler follows the same visible sequence:

```text
Pydantic request/path validation
        ↓
_extract X-Session-ID
        ↓
authenticate session
        ↓
identify subject
        ↓
authorize subject/resource/action/target
        ↓
perform manager/service operation
        ↓
write success or denial audit event
        ↓
return response
```

The operation is not called on a denied authorization path.

## 5. MFA login control flow

```text
password lookup
   |
   +--> invalid password -> increment password failure state -> 401/429
   |
   v
MFA enabled?
   |
   +--> no -> create server-side session
   |
   +--> yes -> require six-digit TOTP
                  |
                  +--> invalid/blocked -> audit -> 401/429; no session
                  |
                  +--> valid -> reset TOTP failure state -> create session
```

## 6. MFA management control flow

Enrollment and disablement are high-impact authentication-factor operations:

```text
existing authenticated session
        ↓
subject derived from session, never request user_id
        ↓
current password re-authentication
        ↓
TOTP verification where required
        ↓
state transition
        ↓
audit event
```

## 7. Dependency and interface constraints

- API depends inward on domain/core.
- Domain depends on ports/core and collaborators, not FastAPI route code.
- Infrastructure implements persistence/runtime concerns.
- No module creates a network boundary for Phase 0/1.
- OAuth/OIDC/token interfaces do not exist yet; creating placeholders would obscure actual behavior.
