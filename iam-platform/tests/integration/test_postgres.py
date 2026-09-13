import os
from collections.abc import Generator
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

psycopg = pytest.importorskip("psycopg")

RUN_INTEGRATION = os.environ.get("IAM_RUN_INTEGRATION_TESTS") == "true"
pytestmark = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="set IAM_RUN_INTEGRATION_TESTS=true to run PostgreSQL integration tests",
)

from app.api.routes import create_router
from app.infrastructure.database import connection, prepare_database
from app.domain.iam import IamService


@pytest.fixture(scope="module")
def integration_context() -> Generator[tuple[IamService, TestClient], None, None]:
    required = (
        "DATABASE_URL",
        "BOOTSTRAP_ADMIN_USERNAME",
        "BOOTSTRAP_ADMIN_PASSWORD",
        "BOOTSTRAP_ADMIN_EMAIL",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        pytest.fail(f"Missing integration environment values: {', '.join(missing)}")

    prepare_database(reset=True)
    service = IamService(connection)
    service.bootstrap(
        os.environ["BOOTSTRAP_ADMIN_USERNAME"],
        os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        os.environ["BOOTSTRAP_ADMIN_EMAIL"],
    )
    application = FastAPI()
    application.include_router(create_router(service))
    with TestClient(application) as client:
        yield service, client


def test_postgres_login_session_and_logout(integration_context: tuple[IamService, TestClient]) -> None:
    _, client = integration_context
    login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    assert login.status_code == 200
    session_id = login.json()["session_id"]
    assert len(session_id) >= 32

    session = client.get("/auth/session", headers={"X-Session-ID": session_id})
    assert session.status_code == 200

    second_login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    assert second_login.status_code == 200
    assert second_login.json()["session_id"] != session_id
    assert os.environ["BOOTSTRAP_ADMIN_USERNAME"] not in session_id

    logout = client.post("/auth/logout", headers={"X-Session-ID": session_id})
    assert logout.status_code == 204
    assert client.get("/auth/session", headers={"X-Session-ID": session_id}).status_code == 401


def test_postgres_protected_operation_distinguishes_401_and_403(integration_context: tuple[IamService, TestClient]) -> None:
    service, client = integration_context
    assert client.get("/applications").status_code == 401

    user = service.create_user("integration-user", "Integration User", "Integration-Password-1", "integration@example.test")
    login = client.post("/auth/login", json={"username": "integration-user", "password": "Integration-Password-1"})
    assert login.status_code == 200
    session_id = login.json()["session_id"]

    denied = client.get("/applications", headers={"X-Session-ID": session_id})
    assert denied.status_code == 403
    assert client.post("/users", headers={"X-Session-ID": session_id}, json={}).status_code == 403
    admin_id = service._one("SELECT id FROM users WHERE username = %s", (os.environ["BOOTSTRAP_ADMIN_USERNAME"],))[0]
    assert client.patch(f"/users/{admin_id}", headers={"X-Session-ID": session_id}, json={"display_name": "IDOR attempt"}).status_code == 403
    assert service._one("SELECT 1 FROM audit_events WHERE event_type = %s AND user_id = %s", ("AUTHORIZATION_DENIED", UUID(str(user["id"]))),) is not None
    assert user["id"]


def test_postgres_login_failures_are_generic_and_throttled(integration_context: tuple[IamService, TestClient]) -> None:
    service, client = integration_context
    service.create_user("lockout-user", "Lockout User", "Correct-Password-1", "lockout@example.test")

    unknown = client.post("/auth/login", json={"username": "missing-user", "password": "wrong"})
    wrong = client.post("/auth/login", json={"username": "lockout-user", "password": "wrong"})
    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert unknown.json() == wrong.json()
    for _ in range(4):
        assert client.post("/auth/login", json={"username": "lockout-user", "password": "wrong"}).status_code == 401
    assert client.post("/auth/login", json={"username": "lockout-user", "password": "Correct-Password-1"}).status_code == 429


def test_postgres_inactive_and_expired_sessions_are_rejected(integration_context: tuple[IamService, TestClient]) -> None:
    service, client = integration_context
    inactive = service.create_user("inactive-user", "Inactive User", "Inactive-Password-1", "inactive@example.test")
    service._execute("UPDATE users SET is_active = FALSE WHERE id = %s", (UUID(str(inactive["id"])),))
    assert client.post("/auth/login", json={"username": "inactive-user", "password": "Inactive-Password-1"}).status_code == 401

    expired_session = "expired-integration-session"
    service._execute(
        "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (%s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP - INTERVAL '1 minute')",
        (expired_session, UUID(str(inactive["id"]))),
    )
    assert client.get("/auth/session", headers={"X-Session-ID": expired_session}).status_code == 401


def test_postgres_authorized_application_operation(integration_context: tuple[IamService, TestClient]) -> None:
    service, client = integration_context
    user = service.create_user("application-admin", "Application Admin", "Integration-Password-2", "application-admin@example.test")
    role = service.create_role("application-reader")
    permissions = [service.create_permission("application", action) for action in ("create", "read", "update", "delete", "deploy")]
    service.assign_role(UUID(str(user["id"])), UUID(role["id"]))
    for permission in permissions:
        service.assign_permission(UUID(role["id"]), UUID(permission["id"]))

    login = client.post("/auth/login", json={"username": "application-admin", "password": "Integration-Password-2"})
    session_id = login.json()["session_id"]
    response = client.post(
        "/applications",
        headers={"X-Session-ID": session_id},
        json={"name": "integration-application", "description": "integration test"},
    )
    assert response.status_code == 201
    application_id = response.json()["id"]
    assert response.json()["name"] == "integration-application"
    assert client.get("/applications", headers={"X-Session-ID": session_id}).status_code == 200
    assert client.get(f"/applications/{application_id}", headers={"X-Session-ID": session_id}).status_code == 200
    assert client.patch(f"/applications/{application_id}", headers={"X-Session-ID": session_id}, json={"description": "updated"}).status_code == 200
    assert client.post(f"/applications/{application_id}/deploy", headers={"X-Session-ID": session_id}).status_code == 200
    assert client.delete(f"/applications/{application_id}", headers={"X-Session-ID": session_id}).status_code == 204


def test_postgres_iam_crud_and_relationship_endpoints(integration_context: tuple[IamService, TestClient]) -> None:
    _, client = integration_context
    login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    session_id = login.json()["session_id"]
    headers = {"X-Session-ID": session_id}

    user = client.post("/users", headers=headers, json={"username": "crud-user", "email": "crud@example.test", "password": "Crud-Password-1", "display_name": "CRUD User"})
    assert user.status_code == 201
    user_id = user.json()["id"]
    assert client.patch(f"/users/{user_id}", headers=headers, json={"display_name": "Updated CRUD User"}).status_code == 200
    group = client.post("/groups", headers=headers, json={"name": "crud-group", "description": "CRUD group"})
    assert group.status_code == 201
    group_id = group.json()["id"]
    role = client.post("/roles", headers=headers, json={"name": "crud-role", "description": "CRUD role"})
    assert role.status_code == 201
    role_id = role.json()["id"]
    permission = client.post("/permissions", headers=headers, json={"resource": "crud", "action": "read"})
    assert permission.status_code == 201
    permission_id = permission.json()["id"]
    assert client.post(f"/users/{user_id}/groups/{group_id}", headers=headers).status_code == 201
    assert client.post(f"/users/{user_id}/roles/{role_id}", headers=headers).status_code == 201
    assert client.post(f"/roles/{role_id}/permissions/{permission_id}", headers=headers).status_code == 201
    assert client.get(f"/users/{user_id}/groups", headers=headers).status_code == 200
    assert client.get(f"/users/{user_id}/roles", headers=headers).status_code == 200
    assert client.get(f"/roles/{role_id}/permissions", headers=headers).status_code == 200
    assert client.delete(f"/roles/{role_id}/permissions/{permission_id}", headers=headers).status_code == 204
    assert client.delete(f"/users/{user_id}/roles/{role_id}", headers=headers).status_code == 204
    assert client.delete(f"/users/{user_id}/groups/{group_id}", headers=headers).status_code == 204
    assert client.delete(f"/permissions/{permission_id}", headers=headers).status_code == 204
    assert client.delete(f"/roles/{role_id}", headers=headers).status_code == 204
    assert client.delete(f"/groups/{group_id}", headers=headers).status_code == 204
    assert client.delete(f"/users/{user_id}", headers=headers).status_code == 204


def test_postgres_audit_is_read_only_and_admin_protected(integration_context: tuple[IamService, TestClient]) -> None:
    _, client = integration_context
    login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    session_id = login.json()["session_id"]
    assert client.get("/audit", headers={"X-Session-ID": session_id}).status_code == 200
    assert client.post("/audit", headers={"X-Session-ID": session_id}, json={}).status_code == 405


def test_postgres_duplicate_identity_and_relationship_attempts_are_rejected(integration_context: tuple[IamService, TestClient]) -> None:
    """Verify database uniqueness constraints prevent duplicate identities and relationship amplification."""
    service, client = integration_context
    login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    headers = {"X-Session-ID": login.json()["session_id"]}
    first = client.post("/users", headers=headers, json={"username": "duplicate-user", "email": "duplicate@example.test", "password": "Password-1", "display_name": "Duplicate User"})
    assert first.status_code == 201
    duplicate = client.post("/users", headers=headers, json={"username": "duplicate-user", "email": "other@example.test", "password": "Password-1", "display_name": "Duplicate User"})
    assert duplicate.status_code == 409

    group = client.post("/groups", headers=headers, json={"name": "duplicate-membership-group"})
    assert group.status_code == 201
    user_id = first.json()["id"]
    group_id = group.json()["id"]
    assert client.post(f"/users/{user_id}/groups/{group_id}", headers=headers).status_code == 201
    assert client.post(f"/users/{user_id}/groups/{group_id}", headers=headers).status_code == 409
    assert service._one("SELECT COUNT(*) FROM user_groups WHERE user_id = %s AND group_id = %s", (UUID(user_id), UUID(group_id)))[0] == 1


def test_postgres_foreign_keys_and_cascades_remove_security_relationships(integration_context: tuple[IamService, TestClient]) -> None:
    """Verify dangling relationship identifiers are rejected and deletion removes inherited privilege edges."""
    service, client = integration_context
    login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    headers = {"X-Session-ID": login.json()["session_id"]}
    user = client.post("/users", headers=headers, json={"username": "cascade-user", "email": "cascade@example.test", "password": "Password-1", "display_name": "Cascade User"}).json()
    role = client.post("/roles", headers=headers, json={"name": "cascade-role"}).json()
    permission = client.post("/permissions", headers=headers, json={"resource": "cascade", "action": "read"}).json()

    assert client.post(f"/users/{user['id']}/roles/{role['id']}", headers=headers).status_code == 201
    assert client.post(f"/roles/{role['id']}/permissions/{permission['id']}", headers=headers).status_code == 201
    assert service._one("SELECT COUNT(*) FROM user_roles WHERE user_id = %s", (UUID(user["id"]),))[0] == 1
    assert client.post(f"/users/{user['id']}/roles/{'00000000-0000-0000-0000-000000000000'}", headers=headers).status_code == 404

    assert client.delete(f"/roles/{role['id']}", headers=headers).status_code == 204
    assert service._one("SELECT COUNT(*) FROM user_roles WHERE user_id = %s", (UUID(user["id"]),))[0] == 0
    assert service._one("SELECT COUNT(*) FROM role_permissions WHERE role_id = %s", (UUID(role["id"]),))[0] == 0


def test_postgres_rejected_payloads_do_not_mutate_users(integration_context: tuple[IamService, TestClient]) -> None:
    """Verify mass-assignment fields and malformed object identifiers cannot change protected state."""
    service, client = integration_context
    login = client.post(
        "/auth/login",
        json={
            "username": os.environ["BOOTSTRAP_ADMIN_USERNAME"],
            "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    headers = {"X-Session-ID": login.json()["session_id"]}
    user = client.post("/users", headers=headers, json={"username": "payload-user", "email": "payload@example.test", "password": "Password-1", "display_name": "Original Name"}).json()

    forged = client.patch(f"/users/{user['id']}", headers=headers, json={"display_name": "Changed", "roles": ["Administrator"]})
    assert forged.status_code == 400
    assert service.get_user(UUID(user["id"]))["display_name"] == "Original Name"
    assert client.get("/users/not-a-uuid", headers=headers).status_code == 422


def test_postgres_authorization_denial_is_recorded_before_state_change(integration_context: tuple[IamService, TestClient]) -> None:
    """Verify a normal user's forbidden application mutation is denied and auditable without changing data."""
    service, client = integration_context
    user = service.create_user("denied-integration-user", "Denied Integration User", "Password-1", "denied-integration@example.test")
    application = service.create_application("denied-integration-app", "original", UUID(user["id"]))
    session_id = client.post("/auth/login", json={"username": "denied-integration-user", "password": "Password-1"}).json()["session_id"]

    response = client.patch(f"/applications/{application['id']}", headers={"X-Session-ID": session_id}, json={"description": "forged"})
    assert response.status_code == 403
    assert service.get_application(UUID(application["id"]))["description"] == "original"
    assert service._one("SELECT 1 FROM audit_events WHERE event_type = %s AND user_id = %s AND result = %s", ("AUTHORIZATION_DENIED", UUID(user["id"]), "denied")) is not None
