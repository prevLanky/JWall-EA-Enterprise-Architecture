# Project Structure

The repository uses explicit responsibility boundaries:

```text
iam-platform/
├── app/
│   ├── api/             HTTP transport and route registration
│   ├── core/            Shared errors, status codes, and validation
│   ├── domain/          Identity, authentication, authorization, audit, application, and database protocols
│   ├── infrastructure/  PostgreSQL schema/connection and Docker runtime adapter
│   ├── dev/             Development-only reset/reload launcher
│   ├── application.py   FastAPI composition root
│   └── main.py          Production application entry point
├── tests/
│   ├── unit/            Fast, dependency-free behavior tests
│   └── integration/     Opt-in PostgreSQL-backed HTTP tests
├── docs/                Architecture, functionality, security, flows, threat model, and schema documentation
├── .env.example         Safe configuration template; no real secrets
├── .env                 Local ignored configuration; never commit
└── docker-compose.yml   PostgreSQL development service only
```

## Visibility conventions

Python does not have C++ translation-unit visibility, so the project uses explicit package APIs:

- Package `__init__.py` files define public exports with `__all__`.
- Names beginning with `_` are implementation details and should not be imported by other layers.
- `app.api` exposes `create_router`; routes do not own persistence.
- `app.domain` exposes `IamService`; authorization and state changes live there.
- `app.infrastructure` contains adapters and is used by composition/startup code.
- `app.dev` is development-only and must not be imported by domain or API modules.
- Tests may use lower-level doubles and adapters, but production layers depend inward on domain/core contracts.

## Development versus production

Production application code is under `app/`, except `app/dev/`. The normal composition is
`app.main:app`. The development launcher is `python -m app.dev.server`; it may reset the local
PostgreSQL database once before starting reload mode. File reloads do not reset the database.

Unit tests run without PostgreSQL. Integration tests are opt-in with
`IAM_RUN_INTEGRATION_TESTS=true` and require a local `DATABASE_URL`. Test code never becomes part
of the runtime package.

## Import direction

```text
api -> domain/core
application -> api/domain
infrastructure -> domain contracts
main -> application/domain/infrastructure
 dev -> infrastructure and Uvicorn
```

New features should be placed beside the responsibility they own. Do not add a second database
adapter in `api/`, put route logic in `domain/`, or place production behavior in `dev/`.
