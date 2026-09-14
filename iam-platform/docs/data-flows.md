# IAM Platform Data Flows

## 1. Data classification

| Data | Classification | Storage/handling |
| --- | --- | --- |
| Password plaintext | Secret | Exists only transiently during request; never stored/logged. |
| Password hash | Credential verifier | `users.password_hash`; Argon2id for new hashes. |
| Raw session ID | Bearer secret | Login response/browser memory; sent in `X-Session-ID`; never stored. |
| Session hash | Sensitive security state | `sessions.id_hash`; SHA-256 digest. |
| TOTP secret | MFA secret | Encrypted Fernet ciphertext in `totp_mfa.encrypted_secret`; never returned after enrollment. |
| TOTP encryption key | Root secret | External `TOTP_ENCRYPTION_KEY`; never stored in DB. |
| Password reset token | One-time bearer secret | Raw delivery value is transient; SHA-256 digest stored in `password_reset_tokens.token_hash`. |
| OTP code | Transient authentication input | Compared in memory; never stored or audited. |
| Audit metadata | Security evidence | Server-generated, restricted to non-secret context. |

## 2. Standard protected request

```mermaid
sequenceDiagram
    participant C as Client
    participant A as FastAPI API
    participant S as IamService
    participant P as AuthorizationPolicy
    participant D as PostgreSQL
    participant L as AuditWriter

    C->>A: Request + X-Session-ID + body
    A->>A: Pydantic/path validation
    A->>S: authenticate(raw session ID)
    S->>D: hash session ID and query digest
    D-->>S: user, expiry, revocation, active state
    S-->>A: authenticated subject
    A->>S: authorize(subject, resource, action, target)
    S->>P: permission decision
    P-->>S: allow/deny
    S->>L: authorization event
    alt denied
        S-->>A: 403
    else allowed
        A->>S: business operation
        S->>D: parameterized read/write
        S->>L: success event
        S-->>A: result
    end
    A-->>C: controlled HTTP response
```

## 3. Password login data flow

```text
username/password/totp_code
        |
        v
strict request model
        |
        v
user lookup by parameterized username
        |
        v
password hash verification
        |
        +--> invalid: bounded failure counter + generic 401
        |
        v
MFA state lookup
        |
        +--> disabled: issue random session ID
        |
        +--> enabled: decrypt TOTP secret -> verify code -> issue session ID
        |
        v
SHA-256(session ID)
        |
        v
sessions.id_hash + expiry stored
        |
        v
raw session ID returned once
```

No session row is created before MFA succeeds.

## 4. TOTP enrollment flow

```mermaid
sequenceDiagram
    participant C as Authenticated client
    participant A as API
    participant S as IamService
    participant T as TotpService
    participant K as SecretProtector
    participant D as PostgreSQL

    C->>A: POST /auth/mfa/totp/enroll + session + current password
    A->>S: authenticate session
    S->>D: session digest lookup
    A->>S: enroll(subject, current password)
    S->>D: verify active user/password
    S->>T: generate secret + provisioning URI
    T->>K: encrypt secret
    K-->>T: authenticated ciphertext
    T->>D: store ciphertext, enabled=false
    T-->>A: provisioning URI only
    A-->>C: URI
    C->>A: POST /auth/mfa/totp/verify + session + code
    A->>S: verify pending secret
    S->>K: decrypt ciphertext
    S->>T: validate RFC 6238 code
    T-->>S: result
    S->>D: enabled=true or increment failure/block
```

## 5. Password reset flow

```text
email
  |
  v
request endpoint with generic 202 response
  |
  +--> known active account: random reset token -> SHA-256 digest in DB
  |
  +--> unknown account: no token, same response

external delivery integration (future)
  |
  v
raw reset token + new password
  |
  v
hash token -> lookup unused, unexpired digest
  |
  v
Argon2id password update + mark token used + revoke sessions
```

## 6. Audit data flow

Audit events are created by trusted service decisions, not by client-provided event fields. Typical metadata includes action names, relationship IDs, result state, and target identifiers. It excludes passwords, raw session IDs, password hashes, TOTP secrets, encryption keys, reset tokens, and OTP codes.

## 7. Database data flow

All external values are passed as SQL parameters. Dynamic update column lists are constructed only from fixed server-side field choices. PostgreSQL constraints enforce uniqueness, required values, foreign keys, primary keys, and cascades after application validation has run.
