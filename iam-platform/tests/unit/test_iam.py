import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Protocol, cast
from uuid import UUID, uuid4

from httpx import Response
import pytest
from fastapi.testclient import TestClient

from app.api.routes import create_router
from app.application import create_app
from app.core.errors import IamError
from app.domain.iam import IamService
from app.domain.ports import SqlParameter, SqlRow
from fastapi import FastAPI


class TypedTestClient(Protocol):
    def post(self, url: str, *, json: dict[str, str]) -> Response: ...
    def get(self, url: str) -> Response: ...


SCHEMA = """
CREATE TABLE users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE,
    display_name TEXT NOT NULL, password_hash TEXT, is_active INTEGER NOT NULL DEFAULT 1,
    failed_login_count INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMP,
    updated_at TIMESTAMP
);
CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL DEFAULT '');
CREATE TABLE user_groups (user_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (user_id, group_id));
CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL DEFAULT '');
CREATE TABLE user_roles (user_id TEXT NOT NULL, role_id TEXT NOT NULL, PRIMARY KEY (user_id, role_id));
CREATE TABLE permissions (id TEXT PRIMARY KEY, resource TEXT NOT NULL, action TEXT NOT NULL, UNIQUE (resource, action));
CREATE TABLE role_permissions (role_id TEXT NOT NULL, permission_id TEXT NOT NULL, PRIMARY KEY (role_id, permission_id));
CREATE TABLE sessions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE applications (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL DEFAULT '', updated_at TIMESTAMP);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP NOT NULL, event_type TEXT NOT NULL,
    user_id TEXT, target_type TEXT NOT NULL, target_id TEXT, result TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}'
);
"""


def _parse_timestamp(value: bytes) -> datetime:
    timestamp = datetime.fromisoformat(value.decode())
    return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=timezone.utc)


class FakeConnection:
    def __init__(self, database: sqlite3.Connection):
        self.database = database

    def __enter__(self):
        return self

    def __exit__(self, exception_type: type[BaseException] | None, exception: BaseException | None, traceback: TracebackType | None) -> bool:
        if exception_type is None:
            self.database.commit()
        else:
            self.database.rollback()
        return False

    def cursor(self) -> "FakeCursor":
        return FakeCursor(self.database.cursor())

    def commit(self) -> None:
        self.database.commit()


class FakeCursor:
    def __init__(self, cursor: sqlite3.Cursor):
        self.cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, exception_type: type[BaseException] | None, exception: BaseException | None, traceback: TracebackType | None) -> bool:
        self.cursor.close()
        return False

    def execute(self, query: str, parameters: tuple[SqlParameter, ...] = ()) -> None:
        # The test double adapts PostgreSQL-style placeholders to SQLite only for behavior tests.
        normalized_parameters = tuple(str(value) if isinstance(value, UUID) else value for value in parameters)
        self.cursor.execute(query.replace("%s", "?"), normalized_parameters)

    def fetchone(self) -> SqlRow | None:
        row = self.cursor.fetchone()
        return tuple(row) if row is not None else None

    def fetchall(self) -> list[SqlRow]:
        return [tuple(row) for row in self.cursor.fetchall()]


@pytest.fixture
def service():
    sqlite3.register_converter("TIMESTAMP", _parse_timestamp)
    database = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    database.executescript(SCHEMA)

    @contextmanager
    def connection_factory() -> Generator[FakeConnection, None, None]:
        yield FakeConnection(database)

    yield IamService(connection_factory)
    database.close()


@pytest.fixture
def client(service: IamService) -> TestClient:
    app = FastAPI()
    app.include_router(create_router(service))
    return TestClient(app)


def test_create_and_retrieve_user(service: IamService) -> None:
    created = service.create_user("alice", "Alice Example")

    assert service.get_user(UUID(str(created["id"]))) == created


def test_duplicate_user_is_rejected(service: IamService) -> None:
    service.create_user("alice", "Alice Example")

    with pytest.raises(IamError):
        service.create_user("alice", "Another Alice")


def test_user_can_be_updated_and_removed(service: IamService) -> None:
    created = service.create_user("alice", "Alice Example")
    user_id = UUID(str(created["id"]))

    updated = service.update_user(user_id, display_name="Alice Updated")
    assert updated["display_name"] == "Alice Updated"

    service.delete_user(user_id)
    with pytest.raises(IamError):
        service.get_user(user_id)


def test_invalid_user_input_is_rejected(service: IamService) -> None:
    with pytest.raises(IamError):
        service.create_user(" ", "Alice Example")


def test_group_membership_and_duplicate_protection(service: IamService) -> None:
    user = service.create_user("alice", "Alice Example")
    group = service.create_group("developers")

    membership = service.add_user_to_group(UUID(str(user["id"])), UUID(str(group["id"])))
    assert membership["group_id"] == group["id"]
    with pytest.raises(IamError):
        service.add_user_to_group(UUID(str(user["id"])), UUID(str(group["id"])))


def test_group_can_be_updated_and_removed(service: IamService) -> None:
    group = service.create_group("developers")
    group_id = UUID(group["id"])

    updated = service.update_group(group_id, name="platform-developers")
    assert updated["name"] == "platform-developers"

    service.delete_group(group_id)
    with pytest.raises(IamError):
        service.get_group(group_id)


def test_role_assignment_and_duplicate_protection(service: IamService) -> None:
    user = service.create_user("alice", "Alice Example")
    role = service.create_role("developer")

    service.assign_role(UUID(str(user["id"])), UUID(str(role["id"])))
    with pytest.raises(IamError):
        service.assign_role(UUID(str(user["id"])), UUID(str(role["id"])))


def test_role_can_be_updated_and_removed(service: IamService) -> None:
    role = service.create_role("developer")
    role_id = UUID(role["id"])

    updated = service.update_role(role_id, name="platform-developer")
    assert updated["name"] == "platform-developer"

    service.delete_role(role_id)
    with pytest.raises(IamError):
        service.get_role(role_id)


def test_effective_permissions_allow_and_deny(service: IamService) -> None:
    user = service.create_user("alice", "Alice Example")
    role = service.create_role("developer")
    permission = service.create_permission("application", "read")
    service.assign_role(UUID(str(user["id"])), UUID(str(role["id"])))
    service.assign_permission(UUID(str(role["id"])), UUID(str(permission["id"])))

    user_id = UUID(str(user["id"]))
    assert service.check_permission(user_id, "application", "read") is True
    assert service.check_permission(user_id, "application", "deploy") is False

    service.remove_permission(UUID(str(role["id"])), UUID(str(permission["id"])))
    assert service.check_permission(user_id, "application", "read") is False


def test_permission_can_be_created_and_removed(service: IamService) -> None:
    permission = service.create_permission("application", "deploy")
    permission_id = UUID(permission["id"])

    assert service.list_permissions() == [permission]
    service.delete_permission(permission_id)
    assert service.list_permissions() == []


def test_relationships_can_be_removed(service: IamService) -> None:
    user = service.create_user("alice", "Alice Example")
    group = service.create_group("developers")
    role = service.create_role("developer")
    permission = service.create_permission("application", "read")
    user_id = UUID(str(user["id"]))
    group_id = UUID(str(group["id"]))
    role_id = UUID(str(role["id"]))
    permission_id = UUID(str(permission["id"]))

    service.add_user_to_group(user_id, group_id)
    service.assign_role(user_id, role_id)
    service.assign_permission(role_id, permission_id)
    assert service.check_permission(user_id, "application", "read") is True

    service.remove_user_from_group(user_id, group_id)
    service.remove_role(user_id, role_id)
    assert service.check_permission(user_id, "application", "read") is False


def test_invalid_object_reference_is_rejected(service: IamService) -> None:
    role = service.create_role("developer")

    with pytest.raises(IamError):
        service.assign_role(uuid4(), UUID(role["id"]))


def test_user_administration_requires_authentication(client: TestClient) -> None:
    typed_client = cast(TypedTestClient, client)
    response = typed_client.post("/users", json={"username": "", "display_name": "Alice"})

    assert response.status_code == 401
    assert response.json()["detail"] == "authentication required"


def test_password_hash_is_not_plaintext() -> None:
    password_hash = IamService.hash_password("correct horse battery staple")

    assert password_hash != "correct horse battery staple"
    assert IamService.verify_password("correct horse battery staple", password_hash)
    assert not IamService.verify_password("wrong password", password_hash)


def test_application_factory_controls_startup_and_health(service: IamService) -> None:
    startup_calls = 0

    def startup_action() -> None:
        nonlocal startup_calls
        startup_calls += 1

    with TestClient(create_app(service, startup_action)) as application_client:
        typed_client = cast(TypedTestClient, application_client)
        response = typed_client.get("/health")

    assert response.json() == {"status": "ok"}
    assert startup_calls == 1


def test_security_login_returns_opaque_session_and_excludes_secrets_from_audit(service: IamService) -> None:
    """Verify successful authentication creates a server-side session without leaking secrets."""
    user = service.create_user("secure-user", "Secure User", "Correct-Password-1", "secure@example.test")

    result = service.login("secure-user", "Correct-Password-1")
    assert result["user_id"] == user["id"]
    assert result["session_id"] not in str(service.audit_events())
    assert "Correct-Password-1" not in str(service.audit_events())
    assert service.authenticate(result["session_id"]) == UUID(str(user["id"]))


def test_security_login_failures_are_generic_and_lock_the_account(service: IamService) -> None:
    """Verify unknown-user and wrong-password responses do not disclose account existence, then throttle."""
    service.create_user("lock-user", "Lock User", "Correct-Password-1", "lock@example.test")

    unknown_error = None
    wrong_password_error = None
    try:
        service.login("missing-user", "wrong")
    except IamError as error:
        unknown_error = error
    try:
        service.login("lock-user", "wrong")
    except IamError as error:
        wrong_password_error = error
    assert unknown_error is not None and wrong_password_error is not None
    assert str(unknown_error) == str(wrong_password_error) == "invalid username or password"

    for _ in range(4):
        with pytest.raises(IamError):
            service.login("lock-user", "wrong")
    with pytest.raises(IamError) as locked:
        service.login("lock-user", "Correct-Password-1")
    assert locked.value.status.value == 429


def test_security_logout_revokes_the_session(service: IamService) -> None:
    """Verify a bearer session cannot be reused after explicit logout."""
    user = service.create_user("logout-user", "Logout User", "Correct-Password-1", "logout@example.test")
    session_id = service.login("logout-user", "Correct-Password-1")["session_id"]

    service.logout(session_id, UUID(str(user["id"])))
    with pytest.raises(IamError):
        service.authenticate(session_id)


def test_security_expired_session_is_rejected(service: IamService) -> None:
    """Verify a session identifier remains unusable after its server-side expiry time."""
    user = service.create_user("expired-user", "Expired User", "Correct-Password-1", "expired@example.test")
    session_id = service.login("expired-user", "Correct-Password-1")["session_id"]
    service._execute(
        "UPDATE sessions SET expires_at = %s WHERE id = %s",
        (datetime.now(timezone.utc) - timedelta(minutes=1), session_id),
    )

    with pytest.raises(IamError):
        service.authenticate(session_id)


def test_security_inactive_user_cannot_authenticate(service: IamService) -> None:
    """Verify deactivation blocks new login attempts and invalidates existing sessions."""
    user = service.create_user("inactive-user", "Inactive User", "Correct-Password-1", "inactive@example.test")
    session_id = service.login("inactive-user", "Correct-Password-1")["session_id"]
    service.update_user(UUID(str(user["id"])), is_active=False)

    with pytest.raises(IamError):
        service.login("inactive-user", "Correct-Password-1")
    with pytest.raises(IamError):
        service.authenticate(session_id)


def test_security_authorization_denies_normal_user_before_application_operation(client: TestClient, service: IamService) -> None:
    """Verify authentication alone does not grant application access or allow an IDOR-style read."""
    user = service.create_user("ordinary-user", "Ordinary User", "Correct-Password-1", "ordinary@example.test")
    target = service.create_application("protected-app", "protected", UUID(str(user["id"])))
    session_id = service.login("ordinary-user", "Correct-Password-1")["session_id"]

    response = client.get(f"/applications/{target['id']}", headers={"X-Session-ID": session_id})
    assert response.status_code == 403


def test_security_privileged_role_cannot_be_renamed_or_deleted(service: IamService) -> None:
    """Verify the bootstrap Administrator role cannot be weakened through CRUD operations."""
    service.bootstrap("admin", "Admin-Password-1", "admin@example.test")
    administrator = UUID(str(service._one("SELECT id FROM roles WHERE name = %s", ("Administrator",))[0]))

    with pytest.raises(IamError):
        service.update_role(administrator, name="ordinary")
    with pytest.raises(IamError):
        service.delete_role(administrator)


def test_security_api_rejects_client_supplied_privilege_fields(client: TestClient, service: IamService) -> None:
    """Verify user creation cannot be used to inject roles, permissions, or audit records."""
    service.bootstrap("admin", "Admin-Password-1", "admin@example.test")
    session_id = service.login("admin", "Admin-Password-1")["session_id"]
    response = client.post(
        "/users",
        headers={"X-Session-ID": session_id},
        json={"username": "forged", "email": "forged@example.test", "password": "Password-1", "role": "Administrator", "audit": "forged"},
    )

    assert response.status_code == 201
    assert "role" not in response.json()
    assert client.post("/audit", headers={"X-Session-ID": session_id}, json={}).status_code == 405


def test_security_username_input_is_parameterized(service: IamService) -> None:
    """Verify SQL metacharacters remain data and cannot turn an invalid login into a valid one."""
    with pytest.raises(IamError) as error:
        service.login("' OR 1=1 --", "anything")
    assert error.value.status.value == 401


def test_security_malformed_password_verifier_fails_closed(service: IamService) -> None:
    """Verify corrupted stored password material cannot turn a login attempt into a server error."""
    user = service.create_user("corrupt-hash-user", "Corrupt Hash User", "Correct-Password-1", "corrupt@example.test")
    service._execute("UPDATE users SET password_hash = %s WHERE id = %s", ("scrypt$not-hex$bad", UUID(str(user["id"]))))

    with pytest.raises(IamError) as error:
        service.login("corrupt-hash-user", "Correct-Password-1")
    assert error.value.status.value == 401


def test_security_successful_login_clears_stale_failure_counter(service: IamService) -> None:
    """Verify an earlier failed attempt does not accumulate into a later avoidable lockout."""
    user = service.create_user("recovery-user", "Recovery User", "Correct-Password-1", "recovery@example.test")
    user_id = UUID(str(user["id"]))
    with pytest.raises(IamError):
        service.login("recovery-user", "wrong")

    service.login("recovery-user", "Correct-Password-1")
    failed_count, locked_until = service._one("SELECT failed_login_count, locked_until FROM users WHERE id = %s", (user_id,))
    assert failed_count == 0
    assert locked_until is None


def test_security_sessions_are_unique_and_deleted_with_the_user(service: IamService) -> None:
    """Verify concurrent-style repeated logins do not share a bearer token and user deletion removes access."""
    user = service.create_user("session-user", "Session User", "Correct-Password-1", "session@example.test")
    user_id = UUID(str(user["id"]))
    first = service.login("session-user", "Correct-Password-1")["session_id"]
    second = service.login("session-user", "Correct-Password-1")["session_id"]
    assert first != second

    service.delete_user(user_id)
    with pytest.raises(IamError):
        service.authenticate(first)
    with pytest.raises(IamError):
        service.authenticate(second)


def test_security_groups_do_not_grant_application_permissions(service: IamService) -> None:
    """Verify identity-only group membership cannot be converted into application privilege."""
    user = service.create_user("group-user", "Group User", "Correct-Password-1", "group@example.test")
    group = service.create_group("application-group")

    service.add_user_to_group(UUID(str(user["id"])), UUID(str(group["id"])))
    assert service.check_permission(UUID(str(user["id"])), "application", "read") is False


def test_security_denied_authorization_is_audited_without_mutating_state(service: IamService) -> None:
    """Verify a denied permission decision leaves the protected operation untouched and records evidence."""
    user = service.create_user("denied-user", "Denied User", "Correct-Password-1", "denied@example.test")
    application = service.create_application("denied-app", "original", UUID(str(user["id"])))

    with pytest.raises(IamError):
        service.authorize(UUID(str(user["id"])), "application", "update", UUID(application["id"]))
    assert service.get_application(UUID(application["id"]))["description"] == "original"
    denied = service.audit_events()[0]
    assert denied["event_type"] == "AUTHORIZATION_DENIED"
    assert denied["result"] == "denied"
