import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import cast

import psycopg

from ..domain.ports import Connection


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (resource, action)
);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT NOT NULL,
    target_id UUID,
    result TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
"""

RESET_SQL = """
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;
"""

EXPECTED_SCHEMA: dict[str, tuple[str, ...]] = {
    "users": ("id", "username", "email", "password_hash", "is_active"),
    "groups": ("id", "name", "description"),
    "user_groups": ("user_id", "group_id"),
    "roles": ("id", "name", "description"),
    "user_roles": ("user_id", "role_id"),
    "permissions": ("id", "resource", "action", "created_at"),
    "role_permissions": ("role_id", "permission_id"),
    "sessions": ("id", "user_id", "expires_at"),
    "applications": ("id", "name"),
    "audit_events": ("id", "event_type", "user_id"),
}


def database_url() -> str:
    configured_url = os.environ.get("DATABASE_URL")
    if configured_url:
        return configured_url
    raise RuntimeError("DATABASE_URL is required. Copy .env.example to .env and set it locally.")


@contextmanager
def connection() -> Generator[Connection, None, None]:
    try:
        with psycopg.connect(database_url(), connect_timeout=5) as database_connection:
            yield cast(Connection, database_connection)
    except psycopg.Error as error:
        raise RuntimeError(
            "PostgreSQL is unavailable. Start PostgreSQL or set DATABASE_URL to a reachable database."
        ) from error


def initialize_schema() -> None:
    with connection() as database_connection:
        with database_connection.cursor() as cursor:
            cursor.execute(SCHEMA_SQL)
        database_connection.commit()
    verify_schema()


def reset_database() -> None:
    """Delete all IAM data so local development starts from a clean database."""

    with connection() as database_connection:
        with database_connection.cursor() as cursor:
            cursor.execute(RESET_SQL)
        database_connection.commit()


def prepare_database(reset: bool = False) -> None:
    """Optionally reset, then create and verify the current development schema."""

    if reset:
        reset_database()
    initialize_schema()


def verify_schema() -> None:
    """Fail startup when the database does not contain the expected current schema."""

    with connection() as database_connection:
        with database_connection.cursor() as cursor:
            cursor.execute(
                """SELECT table_name, column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'"""
            )
            actual_columns = {(row[0], row[1]) for row in cursor.fetchall()}

    missing_columns = [
        f"{table}.{column}"
        for table, columns in EXPECTED_SCHEMA.items()
        for column in columns
        if (table, column) not in actual_columns
    ]
    if missing_columns:
        missing = ", ".join(missing_columns)
        raise RuntimeError(f"PostgreSQL schema is incomplete; missing: {missing}")
