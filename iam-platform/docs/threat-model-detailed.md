# Detailed IAM Threat Model

## 1. Scope

This model covers the current centralized FastAPI IAM service, PostgreSQL persistence, browser helper, local development runtime, and GitHub Actions security pipeline. It does not claim controls for OAuth/OIDC, JWT, federation, SCIM, KMS/HSM, production email delivery, or an application container image because those are not implemented.

## 2. Assets

| Asset | Security property | Primary protection |
| --- | --- | --- |
| User identity | Confidentiality/integrity | Authorization, strict request models, DB constraints |
| Password verifier | Confidentiality/integrity | Argon2id, no plaintext storage, controlled errors |
| Session bearer token | Confidentiality | Random generation, header-only transport assumption, digest storage |
| TOTP secret | Confidentiality/integrity | Fernet authenticated encryption, external key |
| Reset token | Confidentiality/integrity | Random token, digest storage, single-use/expiry |
| Roles/permissions | Integrity | `iam:manage`, protected Administrator role, audit |
| Protected applications | Confidentiality/integrity | Resource/action/target authorization |
| Audit records | Integrity/availability | Trusted server writes, no client write route |
| Database credentials | Confidentiality | Environment/out-of-band secret management |
| CI reports | Controlled disclosure | Artifacts, no secret values in scanner output |

## 3. Actors

- Unauthenticated internet/client attacker.
- Authenticated normal user.
- Attacker who knows UUIDs or usernames.
- Attacker who steals a session header.
- Attacker with database read access.
- Malicious or compromised administrator.
- Malicious pull request author attempting CI abuse.
- Operator/developer running local development mode.

## 4. Trust boundaries

```text
Browser/client
    untrusted headers, bodies, URLs, order, and timing
       |
       v
FastAPI validation and route boundary
       |
       v
Domain policy and service boundary
       |
       v
PostgreSQL connection/data boundary
       |
       v
Local/CI/deployment infrastructure boundary
```

Additional security boundaries:

- `TOTP_ENCRYPTION_KEY` is outside the database and outside source control.
- GitHub Actions scanners run in isolated jobs with read-only repository permissions.
- ZAP targets only a temporary local CI API.

## 5. Abuse cases and mitigations

### TM-01: Password guessing

**Path:** attacker submits repeated invalid passwords.

**Impact:** account compromise or login denial.

**Controls:** Argon2id, generic errors, five-failure/15-minute account lockout, audit events, CI security tests.

**Residual risk:** distributed rate limiting is not implemented; deployment-level throttling is required for public exposure.

### TM-02: TOTP brute force

**Path:** attacker submits many six-digit codes after learning a valid password.

**Impact:** MFA bypass.

**Controls:** TOTP failures are counted per user; five failures produce a 15-minute block; blocked attempts return `429`; success resets the counter; no session is issued before valid TOTP.

**Clock decision:** `valid_window=1` accepts one adjacent 30-second timestep on each side for clock skew. This improves usability but intentionally expands the accepted code set.

### TM-03: MFA enrollment takeover

**Path:** attacker attempts to add a factor to an existing account.

**Impact:** account lockout or future account control.

**Controls:** enrollment requires a valid existing session and current-password re-authentication; user identity comes from the session; enrollment is disabled until code verification; provisioning URI is returned only during enrollment.

### TM-04: MFA disablement bypass

**Path:** attacker calls disable with a guessed user ID or weak/pre-auth token.

**Impact:** removal of second factor.

**Controls:** no request user ID; valid session required; current password and current TOTP required; operation audited.

### TM-05: Session theft/replay

**Path:** attacker obtains `X-Session-ID`.

**Impact:** impersonation until expiry/revocation.

**Controls:** 32-byte URL-safe random token, eight-hour lifetime, SHA-256 digest storage, logout, revoke-all, password-change invalidation, TLS deployment assumption.

**Residual risk:** bearer token remains sufficient for impersonation; no device/IP binding in V1.

### TM-06: Database compromise and session reuse

**Path:** attacker reads sessions table.

**Impact:** direct token reuse if raw sessions were stored.

**Controls:** only `id_hash` is stored; raw token is not recoverable from SHA-256 under normal assumptions.

### TM-07: TOTP database compromise

**Path:** attacker reads `totp_mfa`.

**Impact:** MFA secret recovery.

**Controls:** encrypted secret with authenticated Fernet ciphertext; encryption key is external and not stored with data; tampering causes verification failure.

**Residual risk:** compromise of both database and encryption-key source defeats this boundary; production needs KMS/HSM/Vault.

### TM-08: IDOR/BOLA

**Path:** authenticated user changes a UUID in an application URL.

**Impact:** read/mutate another resource.

**Controls:** resource/action/target authorization occurs before manager operation; target existence is checked; users cannot select the actor identity; negative tests cover known IDs.

### TM-09: Broken function-level authorization

**Path:** normal user calls IAM admin endpoints directly.

**Impact:** role/permission/user escalation.

**Controls:** every IAM admin route requires `iam:manage`; strict request models reject privilege fields; audit records denial.

### TM-10: Mass assignment

**Path:** client adds `role`, `permissions`, `audit`, or security-state fields to JSON.

**Impact:** privilege escalation or forged evidence.

**Controls:** Pydantic models use `extra="forbid"`; service methods accept explicit arguments only.

### TM-11: SQL injection

**Path:** attacker places SQL syntax in username, resource, action, or IDs.

**Impact:** data disclosure or mutation.

**Controls:** parameterized values, bounded validation, fixed server-owned update field lists, database constraints.

### TM-12: Sensitive error disclosure

**Path:** database/service exception reaches client.

**Impact:** schema, SQL, credential, or path disclosure.

**Controls:** expected error mapping and global generic 500 handler; unexpected error test; structured SQLSTATE conflict handling.

### TM-13: Audit manipulation

**Path:** client submits forged audit fields or writes audit endpoint.

**Impact:** loss of evidence integrity.

**Controls:** no client audit-write route; server-generated actor/event/target; sensitive values excluded.

### TM-14: CI supply-chain/configuration failure

**Path:** vulnerable dependency, secret, unsafe source pattern, or misconfiguration enters a pull request.

**Impact:** compromised build or deployment.

**Controls:** Semgrep, Gitleaks, Trivy, Syft/SPDX + Trivy SBOM scan, Pytest/PostgreSQL, ZAP, final gate, read-only GitHub permissions.

### TM-15: Stored or reflected XSS through the admin portal

**Path:** attacker-controlled username, application name, or audit metadata is rendered into the browser portal.

**Impact:** JavaScript execution in the IAM origin, potentially exposing the `sessionStorage` bearer session.

**Controls:** portal rendering uses DOM element creation and `textContent`; no `innerHTML` or `document.write`; CSP, `nosniff`, `no-store`, and `no-referrer` headers are sent; session values are not placed in URLs or rendered data.

**Residual risk:** the portal now uses same-origin external CSS/JavaScript with `script-src 'self'` and `style-src 'self'`. A future production hardening step could add CSP nonces/hashes for any unavoidable inline content, but the current portal has no inline script/style blocks.

### TM-16: Stale browser session after server revocation

**Path:** a revoked/expired session remains in `sessionStorage` and the user continues using the portal.

**Impact:** confusing failures or accidental repeated use of an invalid bearer value.

**Controls:** portal `401` responses clear the storage value and redirect to `/login`; logout clears storage after server revocation; server-side session expiry/revocation remains authoritative.

## 6. Security evidence

- Unit/security suite covers 48 focused tests.
- Full local suite with PostgreSQL has passed 60 tests.
- CI scanner reports are uploaded as artifacts.
- Database schema contains foreign keys, uniqueness, session digests, encrypted TOTP fields, and throttle state.
- Documentation and code keep authentication, authorization, audit, and application operations in explicit modules.

## 7. Residual risks

- No distributed password/TOTP throttling across multiple application instances.
- No recovery codes for MFA.
- No email/SMS delivery for password reset.
- No production KMS/HSM/Vault integration.
- No authenticated DAST of protected endpoints.
- No immutable external audit sink or SIEM forwarding.
- No OAuth/OIDC/JWT/JWKS, workload identity, SCIM, federation, PKI, or container image controls.
- Local demo credentials are intentionally predictable and must never be reused in production.
