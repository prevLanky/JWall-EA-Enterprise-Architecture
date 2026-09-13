import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
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
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL);
CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE user_groups (user_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (user_id, group_id));
CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE user_roles (user_id TEXT NOT NULL, role_id TEXT NOT NULL, PRIMARY KEY (user_id, role_id));
CREATE TABLE permissions (id TEXT PRIMARY KEY, resource TEXT NOT NULL, action TEXT NOT NULL, UNIQUE (resource, action));
CREATE TABLE role_permissions (role_id TEXT NOT NULL, permission_id TEXT NOT NULL, PRIMARY KEY (role_id, permission_id));
"""


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
    database = sqlite3.connect(":memory:")
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
