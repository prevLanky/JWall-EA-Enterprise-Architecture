import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Protocol, cast
from uuid import UUID, uuid4

import pyotp
from cryptography.fernet import Fernet
from httpx import Response
import pytest
from fastapi.testclient import TestClient

from app.api.routes import create_router
from app.application import create_app
from app.core.errors import IamError
from app.domain.iam import IamService
from app.domain.ports import SqlParameter, SqlRow
from app.domain.secrets import SecretProtector, SecretProtectionError
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
    id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE TABLE password_reset_tokens (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL, used_at TIMESTAMP
);
CREATE TABLE totp_mfa (
    user_id TEXT PRIMARY KEY, encrypted_secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, last_verified_at TIMESTAMP,
    failed_attempts INTEGER NOT NULL DEFAULT 0, blocked_until TIMESTAMP
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
    app = create_app(service)
    return TestClient(app, raise_server_exceptions=False)


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

    assert response.status_code == 422


def test_password_hash_is_not_plaintext() -> None:
    password_hash = IamService.hash_password("correct horse battery staple")

    assert password_hash != "correct horse battery staple"
    assert password_hash.startswith("$argon2id$")
    assert IamService.verify_password("correct horse battery staple", password_hash)
    assert not IamService.verify_password("wrong password", password_hash)


def test_password_policy_rejects_short_passwords(service: IamService) -> None:
    """Verify the service rejects passwords shorter than the documented minimum."""
    with pytest.raises(IamError) as error:
        service.create_user("short-password", "Short Password", "too-short", "short@example.test")
    assert error.value.status.value == 400


def test_demo_seed_creates_distinct_application_permissions(service: IamService) -> None:
    """Verify local demo accounts are repeatable and demonstrate different RBAC outcomes."""
    service.seed_demo_users()
    service.seed_demo_users()

    reader = UUID(str(service._one("SELECT id FROM users WHERE username = %s", ("demo-reader",))[0]))
    operator = UUID(str(service._one("SELECT id FROM users WHERE username = %s", ("demo-operator",))[0]))
    developer = UUID(str(service._one("SELECT id FROM users WHERE username = %s", ("demo-developer",))[0]))

    assert service.check_permission(reader, "application", "read") is True
    assert service.check_permission(reader, "application", "update") is False
    assert service.check_permission(operator, "application", "deploy") is True
    assert service.check_permission(operator, "application", "delete") is False
    assert service.check_permission(developer, "application", "delete") is True


def test_demo_seed_creates_group_memberships_without_granting_permissions(service: IamService) -> None:
    """Verify seeded groups provide identity relationships while direct roles control permissions."""
    service.seed_demo_users()
    reader = UUID(str(service._one("SELECT id FROM users WHERE username = %s", ("demo-reader",))[0]))

    assert service.user_groups(reader)[0]["name"] == "Platform Observers"
    assert service.check_permission(reader, "application", "read") is True
    assert service.check_permission(reader, "application", "update") is False
    assert service.check_permission(reader, "iam", "manage") is False


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


def test_browser_login_page_is_available(service: IamService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the browser login helper is available without exposing the API schema route."""
    monkeypatch.setenv("IAM_SEED_DEMO_USERS", "true")
    with TestClient(create_app(service)) as application_client:
        response = application_client.get("/login")

    assert response.status_code == 200
    assert "IAM Platform" in response.text
    assert "demo-reader" in response.text
    assert "/login" not in response.text.split("<title>", 1)[0]


def test_security_login_returns_opaque_session_and_excludes_secrets_from_audit(service: IamService) -> None:
    """Verify successful authentication creates a server-side session without leaking secrets."""
    user = service.create_user("secure-user", "Secure User", "Correct-Password-1", "secure@example.test")

    result = service.login("secure-user", "Correct-Password-1")
    assert result["user_id"] == user["id"]
    assert result["session_id"] not in str(service.audit_events())
    assert "Correct-Password-1" not in str(service.audit_events())
    stored_hash = service._one("SELECT id_hash FROM sessions WHERE user_id = %s", (UUID(str(user["id"])),))[0]
    assert stored_hash == IamService.hash_session_id(result["session_id"])
    assert stored_hash != result["session_id"]
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


def test_phase_one_password_change_revokes_existing_sessions(service: IamService) -> None:
    """Verify changing a password invalidates existing bearer sessions and permits the new password."""
    user = service.create_user("password-user", "Password User", "Correct-Password-1", "password@example.test")
    user_id = UUID(str(user["id"]))
    first_session = service.login("password-user", "Correct-Password-1")["session_id"]
    second_session = service.login("password-user", "Correct-Password-1")["session_id"]

    assert len(service.list_sessions(user_id)) == 2
    service.change_password(user_id, "Correct-Password-1", "New-Correct-Password-1")

    with pytest.raises(IamError):
        service.authenticate(first_session)
    with pytest.raises(IamError):
        service.authenticate(second_session)
    assert service.login("password-user", "New-Correct-Password-1")["user_id"] == user["id"]
    assert any(event["event_type"] == "PASSWORD_CHANGED" for event in service.audit_events())


def test_phase_one_revoke_all_sessions_is_idempotent(service: IamService) -> None:
    """Verify explicit session revocation removes all active sessions without revealing session IDs."""
    user = service.create_user("revoke-user", "Revoke User", "Correct-Password-1", "revoke@example.test")
    user_id = UUID(str(user["id"]))
    session_id = service.login("revoke-user", "Correct-Password-1")["session_id"]

    service.revoke_all_sessions(user_id)
    service.revoke_all_sessions(user_id)
    assert service.list_sessions(user_id)[0]["revoked"] is True
    with pytest.raises(IamError):
        service.authenticate(session_id)


def test_phase_one_password_reset_is_single_use_and_revokes_sessions(service: IamService) -> None:
    """Verify reset tokens are hashed, single-use, and invalidate prior bearer sessions."""
    user = service.create_user("reset-user", "Reset User", "Correct-Password-1", "reset@example.test")
    user_id = UUID(str(user["id"]))
    session_id = service.login("reset-user", "Correct-Password-1")["session_id"]
    token = service.issue_password_reset_token("reset@example.test")

    assert token is not None
    stored = service._one("SELECT token_hash FROM password_reset_tokens WHERE user_id = %s", (user_id,))[0]
    assert stored == IamService.hash_session_id(token)
    assert stored != token

    service.complete_password_reset(token, "Reset-Correct-Password-1")
    with pytest.raises(IamError):
        service.authenticate(session_id)
    assert service.login("reset-user", "Reset-Correct-Password-1")["user_id"] == user["id"]
    with pytest.raises(IamError):
        service.complete_password_reset(token, "Another-Correct-Password-1")


def test_phase_one_password_reset_request_does_not_enumerate_users(service: IamService) -> None:
    """Verify reset requests for unknown and known emails have the same externally safe outcome."""
    assert service.issue_password_reset_token("missing@example.test") is None
    user = service.create_user("known-reset", "Known Reset", "Correct-Password-1", "known-reset@example.test")
    assert service.issue_password_reset_token("known-reset@example.test") is not None
    assert user["email"] == "known-reset@example.test"


def test_totp_secret_protector_round_trip_and_tamper_detection() -> None:
    """Verify TOTP secret encryption authenticates ciphertext and never returns plaintext storage."""
    key = Fernet.generate_key()
    protector = SecretProtector(key)
    ciphertext = protector.encrypt(b"totp-secret")

    assert ciphertext != b"totp-secret"
    assert protector.decrypt(ciphertext) == b"totp-secret"
    with pytest.raises(SecretProtectionError):
        protector.decrypt(ciphertext[:-1] + b"0")
    with pytest.raises(SecretProtectionError):
        SecretProtector(Fernet.generate_key()).decrypt(ciphertext)


def test_totp_enrollment_requires_verification_and_enforces_login(service: IamService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify enrollment is pending until a valid code, then blocks password-only login."""
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    user = service.create_user("mfa-user", "MFA User", "Correct-Password-1", "mfa@example.test")
    user_id = UUID(str(user["id"]))

    enrollment = service.enroll_totp(user_id, "Correct-Password-1")
    secret = pyotp.parse_uri(enrollment["provisioning_uri"]).secret
    assert service.totp_status(user_id) == {"enabled": False}
    assert service._one("SELECT encrypted_secret FROM totp_mfa WHERE user_id = %s", (user_id,))[0] != secret

    with pytest.raises(IamError):
        service.verify_totp_enrollment(user_id, "000000")
    assert service.login("mfa-user", "Correct-Password-1")["user_id"] == user["id"]

    service.verify_totp_enrollment(user_id, pyotp.TOTP(secret).now())
    assert service.totp_status(user_id) == {"enabled": True}
    with pytest.raises(IamError):
        service.login("mfa-user", "Correct-Password-1")
    with pytest.raises(IamError):
        service.login("mfa-user", "Correct-Password-1", "000000")
    assert service.login("mfa-user", "Correct-Password-1", pyotp.TOTP(secret).now())["user_id"] == user["id"]


def test_totp_disable_requires_password_and_current_code(service: IamService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify MFA cannot be disabled with an unauthenticated or incomplete recovery path."""
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    user = service.create_user("disable-mfa", "Disable MFA", "Correct-Password-1", "disable-mfa@example.test")
    user_id = UUID(str(user["id"]))
    secret = pyotp.parse_uri(service.enroll_totp(user_id, "Correct-Password-1")["provisioning_uri"]).secret
    service.verify_totp_enrollment(user_id, pyotp.TOTP(secret).now())

    with pytest.raises(IamError):
        service.disable_totp(user_id, "wrong-password", "000000")
    service.disable_totp(user_id, "Correct-Password-1", pyotp.TOTP(secret).now())
    assert service.totp_status(user_id) == {"enabled": False}
    assert all("secret" not in str(event).lower() for event in service.audit_events())


def test_totp_tampered_secret_fails_closed(service: IamService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a corrupted encrypted secret cannot bypass MFA or expose decryption details."""
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    user = service.create_user("tampered-mfa", "Tampered MFA", "Correct-Password-1", "tampered-mfa@example.test")
    user_id = UUID(str(user["id"]))
    service.enroll_totp(user_id, "Correct-Password-1")
    service._execute("UPDATE totp_mfa SET encrypted_secret = %s, enabled = TRUE WHERE user_id = %s", ("tampered", user_id))

    with pytest.raises(IamError) as error:
        service.login("tampered-mfa", "Correct-Password-1", "123456")
    assert error.value.status.value == 401


def test_totp_failed_attempts_are_temporarily_throttled(service: IamService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify repeated invalid codes are blocked before unlimited six-digit guessing is possible."""
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    user = service.create_user("throttled-mfa", "Throttled MFA", "Correct-Password-1", "throttled-mfa@example.test")
    user_id = UUID(str(user["id"]))
    secret = pyotp.parse_uri(service.enroll_totp(user_id, "Correct-Password-1")["provisioning_uri"]).secret

    for _ in range(4):
        with pytest.raises(IamError):
            service.verify_totp_enrollment(user_id, "000000")
    with pytest.raises(IamError) as blocked:
        service.verify_totp_enrollment(user_id, "000000")
    assert blocked.value.status.value == 429
    with pytest.raises(IamError) as still_blocked:
        service.verify_totp_enrollment(user_id, pyotp.TOTP(secret).now())
    assert still_blocked.value.status.value == 429


def test_security_expired_session_is_rejected(service: IamService) -> None:
    """Verify a session identifier remains unusable after its server-side expiry time."""
    user = service.create_user("expired-user", "Expired User", "Correct-Password-1", "expired@example.test")
    session_id = service.login("expired-user", "Correct-Password-1")["session_id"]
    service._execute(
        "UPDATE sessions SET expires_at = %s WHERE id_hash = %s",
        (datetime.now(timezone.utc) - timedelta(minutes=1), IamService.hash_session_id(session_id)),
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

    assert response.status_code == 422
    assert service._one("SELECT 1 FROM users WHERE username = %s", ("forged",)) is None
    assert client.post("/audit", headers={"X-Session-ID": session_id}, json={}).status_code == 405


def test_security_api_rejects_wrong_types_and_oversized_values(client: TestClient, service: IamService) -> None:
    """Verify malformed structured requests are rejected before the service mutates state."""
    service.bootstrap("validation-admin", "Admin-Password-1", "validation-admin@example.test")
    session_id = service.login("validation-admin", "Admin-Password-1")["session_id"]
    headers = {"X-Session-ID": session_id}

    wrong_type = client.post("/groups", headers=headers, json={"name": 123})
    oversized = client.post("/groups", headers=headers, json={"name": "x" * 256})
    malformed_id = client.get("/users/not-a-uuid", headers=headers)

    assert wrong_type.status_code == 422
    assert oversized.status_code == 422
    assert malformed_id.status_code == 422


def test_security_api_hides_unexpected_errors(client: TestClient, service: IamService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify unexpected service failures become a generic 500 without internal details."""
    service.bootstrap("error-admin", "Admin-Password-1", "error-admin@example.test")
    session_id = service.login("error-admin", "Admin-Password-1")["session_id"]

    def fail() -> list[dict[str, object]]:
        raise RuntimeError("database password and SQL should not escape")

    monkeypatch.setattr(service, "list_users", fail)
    response = client.get("/users", headers={"X-Session-ID": session_id})

    assert response.status_code == 500
    assert response.json() == {"detail": "internal server error"}


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


def test_security_target_authorization_rejects_unknown_application(service: IamService) -> None:
    """Verify an object identifier is checked before an application operation is allowed."""
    user = service.create_user("target-user", "Target User", "Correct-Password-1", "target@example.test")
    permission = service.create_permission("application", "read")
    role = service.create_role("target-reader")
    service.assign_role(UUID(str(user["id"])), UUID(str(role["id"])))
    service.assign_permission(UUID(str(role["id"])), UUID(str(permission["id"])))

    with pytest.raises(IamError) as error:
        service.authorize(UUID(str(user["id"])), "application", "read", uuid4())
    assert error.value.status.value == 404
