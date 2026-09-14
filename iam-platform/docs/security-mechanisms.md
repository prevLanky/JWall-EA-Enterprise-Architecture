# Security Mechanisms Reference

## 1. Defense-in-depth model

Security is enforced at multiple boundaries because no single layer is trusted to remain correct forever.

```text
Untrusted request
      |
      v
API validation: types, lengths, unknown-field rejection, UUID parsing
      |
      v
Authentication: password/session/MFA state
      |
      v
Authorization: subject/resource/action/target decision
      |
      v
Domain operation: business invariants and state transitions
      |
      v
Parameterized SQL + PostgreSQL constraints
      |
      v
Audit event and controlled response
```

A direct service caller still encounters service validation and business rules. A database caller still encounters relational constraints, but database credentials are an infrastructure boundary rather than an application authorization mechanism.

## 2. Password security

New passwords require at least 12 characters and are hashed with configurable Argon2id parameters:

- `ARGON2_TIME_COST` defaults to `3`.
- `ARGON2_MEMORY_COST_KIB` defaults to `65536`.
- `ARGON2_PARALLELISM` defaults to `2`.

The password plaintext is used only during the request operation. It is not returned, logged, audited, or stored. Legacy bcrypt and scrypt hashes remain verifiable to support migration, but new hashes never silently fall back to those algorithms.

Wrong-password behavior is generic and does not distinguish an unknown username from a known username. Five failed password attempts produce a 15-minute account block. A successful login resets stale failure state.

## 3. Session security

Sessions are opaque bearer credentials generated with a cryptographically secure URL-safe random generator. The raw value is returned only in the login response and sent by clients in `X-Session-ID`.

```text
raw session ID -> SHA-256 digest -> sessions.id_hash
```

Authentication hashes the supplied header before lookup and checks:

- Existence.
- Expiration.
- Revocation.
- Active user state.

Sessions are revoked by logout, password change, password reset, revoke-all, and user deletion cascades. The API does not put session values in URLs or audit records. The browser helper stores the raw value in session-scoped browser storage; production deployments must provide TLS because possession of the value is sufficient for impersonation.

## 4. TOTP MFA

TOTP uses the established `pyotp` library and RFC 6238 semantics. The configured clock policy is explicit:

- 30-second standard timestep.
- `valid_window=1`, accepting one adjacent timestep on either side for modest clock drift.
- Six-digit codes.

The TOTP secret is not a password hash because verification requires decryption. It is protected as follows:

```text
random TOTP secret
      |
      v
SecretProtector.encrypt()
      |
      v
Fernet authenticated ciphertext in totp_mfa.encrypted_secret
```

The Fernet key is loaded from `TOTP_ENCRYPTION_KEY`; it is not stored alongside ciphertext. The `SecretProtector` interface allows later KMS/HSM/Vault replacement without changing TOTP logic.

Enrollment requires:

1. A valid existing session.
2. Current-password re-authentication.
3. Generation and encrypted persistence of a disabled secret.
4. Successful code verification before enabling MFA.

MFA login requires password and TOTP before any session row is created. Five failed TOTP attempts create a 15-minute per-user block. The counter is updated atomically and successful verification resets it. Blocked attempts return `429` and are audited without secret data.

Disablement requires the existing session, current password, and current TOTP code. No endpoint accepts another user's ID for MFA management.

## 5. Password reset security

Reset requests always return the same generic response. For an active matching email, the service generates a random reset token, stores only its SHA-256 digest, and expects delivery to be handled by a future external integration.

Completion requires an unused, unexpired digest match. Completion marks the token used, replaces the password hash, revokes all sessions, and audits the transition. Raw reset tokens do not appear in database rows, responses other than the future delivery boundary, or logs.

## 6. Authorization

Authorization uses direct role-to-permission relationships:

```text
user -> user_roles -> roles -> role_permissions -> permissions(resource, action)
```

Groups are identity-only and do not grant permissions in V1. IAM administration requires `iam:manage`. Application actions use resource permissions such as `application:read` and `application:deploy`.

Target-aware checks validate an application target exists before the operation proceeds. The current V1 policy is not an ownership policy and does not yet evaluate context such as environment, device compliance, or MFA state beyond the authentication gate.

## 7. Request validation

Pydantic models use `extra="forbid"`, bounded string lengths, explicit types, and constrained six-digit MFA values. UUID path parameters are parsed by FastAPI. Validation occurs before route operations and service validation repeats important business/security rules.

This prevents:

- Mass assignment.
- Privilege fields hidden in arbitrary JSON.
- Oversized input abuse.
- Malformed identifier crashes.
- Unexpected field drift.

## 8. SQL and database integrity

SQL values are parameterized. Partial-update field lists are selected from fixed server-owned choices, never from client-provided identifiers. PostgreSQL enforces:

- `NOT NULL` required values.
- Unique identities and names.
- Foreign-key relationships.
- Primary-key relationship uniqueness.
- Cascading cleanup.

Expected uniqueness conflicts use structured SQLSTATE/class detection rather than human-readable exception text.

## 9. Error handling

Expected errors map to stable HTTP categories. Unexpected failures cross a global application boundary and become a generic `500 internal server error` response. Internal SQL, stack traces, file paths, credentials, OTP codes, and encryption errors are not returned to clients.

Authentication and MFA failures intentionally use generic messages where account or factor existence could otherwise be enumerated.

## 10. Audit controls

Audit events are written by the trusted service boundary. Clients cannot choose the actor or forge event results. Events cover:

- Login success/failure.
- Authorization allowed/denied.
- Password changes and resets.
- Session revocation.
- MFA enrollment, verification, throttling, and disablement.
- Administrative identity/role/permission changes.
- Protected application changes.

Sensitive values are excluded from event metadata.

## 11. Operational controls

- PostgreSQL credentials are supplied out of band.
- `.env` is ignored and `.env.example` contains placeholders only.
- CI uses temporary credentials and service containers.
- GitHub Actions permissions are read-only for repository contents.
- Semgrep, Gitleaks, Trivy, Syft/SPDX, Pytest, and ZAP jobs gate pull requests/pushes.
- Production deployments must provide TLS, secret management, distributed throttling, and external audit durability.

## 12. Browser portal defenses

The `/admin` page is a presentation shell, not an authorization boundary. It can be downloaded by
an unauthenticated or normal user, but its data and actions are API requests that require the
existing session and permissions.

Portal-specific controls include:

- API values are inserted with DOM `textContent` and element construction, not `innerHTML` or
      `document.write`.
- The page returns a Content Security Policy with same-origin defaults, `script-src 'self'`,
  `style-src 'self'`, no objects, no base URI, and no framing. Browser assets are served from the
  same-origin `/static` mount; the portal no longer requires `unsafe-inline`.
- `X-Content-Type-Options: nosniff` prevents MIME guessing.
- `Referrer-Policy: no-referrer` prevents referrer leakage.
- `Cache-Control: no-store` prevents browser/proxy caching of the portal shell.
- A `401` API response removes `iam-session-id` from `sessionStorage` and redirects to `/login`.
- Logout removes the browser session value after attempting server-side revocation.
- Session IDs are not placed in URLs, logs, rendered table data, or audit output.

The portal displays attacker-controlled fields such as usernames, application names, and audit
metadata. The DOM-only rendering rule is therefore a security invariant, not merely a style choice.
