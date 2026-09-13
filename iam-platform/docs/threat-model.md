# IAM V1 Threat Model

## Assets

User identities, password verifiers, sessions, roles, permissions, application records, audit
records, and administrative privileges are security-sensitive assets.

## Actors and boundaries

Actors are unauthenticated attackers, authenticated normal users, compromised accounts, malicious
administrators, and attackers who know object identifiers. The client is untrusted. FastAPI is the
trusted policy enforcement point. PostgreSQL is trusted for persistence but protected by database
credentials and constraints.

```text
Client -> FastAPI authentication/authorization boundary -> PostgreSQL data boundary
```

## Threats and mitigations

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| Credential attacks | Password hashing, generic failures, five-failure lockout | Authentication tests |
| Authentication bypass | Opaque sessions, expiration, revocation, active-user check | Session tests |
| Session fixation or theft | Random server-side identifiers and logout revocation | Session tests |
| IDOR | Authorization precedes object operation | Protected resource tests |
| Horizontal escalation | Centralized permission checks on every protected endpoint | Authorization tests |
| Vertical escalation | Only `iam:manage` permits IAM administration | Privilege tests |
| SQL injection | Parameterized database queries and validation | Service implementation |
| Audit manipulation | No client audit endpoint; events are server generated | Audit tests |
| Information disclosure | Generic login errors and controlled HTTP errors | Authentication tests |
| Login denial of service | Bounded lockout duration and explicit failure counter | Login protection tests |
| Compromised administrator | Least-privilege role assignment and audit evidence | Administrative audit events |

## Residual risk

TLS termination, secret storage, distributed throttling, MFA, external audit immutability, and
operational alerting remain deployment responsibilities or future V2 work.
