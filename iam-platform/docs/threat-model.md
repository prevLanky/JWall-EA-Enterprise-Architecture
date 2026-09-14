# IAM V1 Threat Model

This threat model describes the security boundary of the V1 IAM platform and the abuse cases
covered by the security test suite. It is intentionally scoped to the application and its
PostgreSQL boundary; deployment controls are listed as residual risk.

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

### Trust assumptions

- The client controls headers, JSON fields, URL identifiers, and request ordering.
- Route handlers and the service are trusted application code; authorization must therefore be
  enforced on every protected route and before the operation it protects.
- PostgreSQL is trusted to execute parameterized statements and enforce foreign keys, uniqueness,
  and cascade behavior. Database credentials remain outside the application source tree.
- TLS is terminated before the API, so session confidentiality in transit is a deployment control.

### Security objectives

1. Only active users with valid, unexpired, non-revoked sessions can authenticate to protected
	operations.
2. A user can perform only actions granted by direct role permissions; object identifiers do not
	bypass authorization.
3. Password verifiers and session identifiers are not disclosed, and audit records are generated
	only by trusted server code.
4. Administrative changes leave evidence and cannot weaken the protected Administrator role.

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

## Abuse cases and attack paths

| ID | Attack path | Impact | Control and test |
| --- | --- | --- | --- |
| TM-01 | Submit a missing, expired, revoked, or stolen-looking session identifier | Unauthorized access | Server-side session lookup, expiry, revocation, and active-user checks; session tests |
| TM-02 | Enumerate usernames using different login errors | Account discovery | Generic invalid-login response; login failure test |
| TM-03 | Repeatedly guess a valid user's password | Account compromise or availability loss | Five-failure, fifteen-minute lockout; throttling test |
| TM-04 | Read or mutate another object by changing its UUID | Horizontal privilege escalation | Per-request authorization before lookup/mutation; IDOR test |
| TM-05 | Add role, permission, or audit fields to a user request | Vertical privilege escalation or evidence forgery | Explicit input allow-list and server-generated audit; privilege-field test |
| TM-06 | Rename or delete the Administrator role | Loss of administrative policy integrity | Protected-role invariant; privileged-role test |
| TM-07 | Place SQL syntax in a username or resource identifier | Data disclosure or authentication bypass | Bound SQL parameters and input validation; injection test |
| TM-08 | Read audit output or error responses for secrets | Credential/session disclosure | Secret exclusion and generic errors; audit confidentiality test |
| TM-09 | Submit duplicate identities or relationship edges | Integrity corruption or privilege amplification | Database uniqueness and primary-key constraints; PostgreSQL constraint tests |
| TM-10 | Reference deleted or nonexistent relationship objects | Dangling privilege edges or inconsistent authorization | Foreign keys, existence checks, and cascade tests |
| TM-11 | Add unsupported fields or malformed object identifiers to mutation requests | Mass assignment or validation bypass | Route allow-lists and framework UUID validation; payload tests |
| TM-12 | Corrupt a stored password verifier | Authentication error disclosure or availability failure | Fail-closed verifier handling; malformed-verifier test |
| TM-13 | Accumulate old login failures across successful sessions | Avoidable account lockout | Reset failure state after successful login; recovery test |
| TM-14 | Steal database contents and reuse stored session credentials | Session impersonation | Store only SHA-256 session digests; hash-session test |
| TM-15 | Submit malformed or mass-assignment request bodies | Validation bypass or state corruption | Strict Pydantic models with forbidden extra fields; API validation tests |
| TM-16 | Trigger an unexpected database or service failure | Information disclosure or unsafe continuation | Global generic 500 boundary and fail-closed operation flow; error test |

## Test traceability

The executable test docstrings state the purpose of each security test. The default unit suite is
offline and uses an in-memory SQLite adapter with the production table shape. PostgreSQL tests in
`tests/integration/test_postgres.py` remain the authoritative compatibility checks for database
types, constraints, expiry comparisons, and deployment wiring; run them with
`IAM_RUN_INTEGRATION_TESTS=true` and the required environment values.

## Residual risk

TLS termination, secret storage, distributed throttling, MFA, external audit immutability, and
operational alerting remain deployment responsibilities or future V2 work. Session identifiers are
still bearer credentials: anyone who obtains the raw header value can act as that user until
expiration or revocation. V1 intentionally does not bind sessions to IP addresses, devices, or
browsers because those controls create reliability and legitimate-client mobility problems.
