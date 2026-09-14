# IAM Platform Documentation

This is the documentation map for the IAM Platform V1 and Phase 1 implementation. The project is a single FastAPI application with PostgreSQL persistence. The internal modules are separated by responsibility, but they do not communicate over the network and are not microservices.

## Reference documents

| Document | Purpose |
| --- | --- |
| [Architecture](architecture-detailed.md) | Components, ownership, composition, dependency direction, lifecycle, and extension boundaries. |
| [Functionality](functionality.md) | User-visible capabilities, endpoint catalog, roles, permissions, demo accounts, and expected outcomes. |
| [Security mechanisms](security-mechanisms.md) | Authentication, MFA, authorization, validation, encryption, error handling, audit, and database controls. |
| [Data flows](data-flows.md) | Request, authentication, password reset, TOTP, authorization, persistence, and audit data movement. |
| [Control flows and interfaces](control-flows-and-interfaces.md) | Step-by-step protected-request behavior and stable internal/API contracts. |
| [Threat model](threat-model-detailed.md) | Assets, actors, trust boundaries, abuse cases, mitigations, evidence, and residual risk. |
| [DevSecOps pipeline](devsecops-security-pipeline.md) | CI triggers, scanners, test environment, artifacts, gates, and limitations. |
| [Security model](security.md) | Concise security policy and regression-test inventory. |
| [Database schema](schema.sql) | PostgreSQL DDL and relational constraints. |

## Current implementation status

- IAM core modularization: complete.
- Password authentication and server-side sessions: complete.
- Password change, reset architecture, session listing, revocation, and revoke-all: complete.
- TOTP MFA with encrypted secrets, re-authentication, throttling, and clock-skew policy: complete.
- Same-origin admin portal with strict external-asset CSP: complete.
- OAuth 2.0, OIDC, JWT/JWKS, workload identity, SCIM, federation, Secrets Broker, and PKI: intentionally deferred.

## Security reading order

For a security review, read [Architecture](architecture-detailed.md), then [Security mechanisms](security-mechanisms.md), [Control flows and interfaces](control-flows-and-interfaces.md), and [Threat model](threat-model-detailed.md). Use [Data flows](data-flows.md) to trace where credentials and sensitive values move.
