from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

try:
    import bcrypt
except ImportError:  # requirements.txt supplies bcrypt in deployments.
    bcrypt = None

from ..core.errors import conflict, forbidden, not_found, too_many_requests, unauthorized
from ..core.validation import require_text
from .ports import ConnectionFactory, SqlParameter, SqlRow

__all__ = ["IamService"]

SESSION_LIFETIME = timedelta(hours=8)


class IamService:
    """Application service containing authentication, RBAC, and audit decisions."""

    def __init__(self, connection_factory: ConnectionFactory):
        self.connection_factory = connection_factory

    def _one(self, query: str, parameters: tuple[SqlParameter, ...] = ()) -> SqlRow | None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, parameters)
                return cursor.fetchone()

    def _all(self, query: str, parameters: tuple[SqlParameter, ...] = ()) -> list[SqlRow]:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, parameters)
                return cursor.fetchall()

    def _execute(self, query: str, parameters: tuple[SqlParameter, ...] = ()) -> None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, parameters)
            connection.commit()

    @staticmethod
    def hash_password(password: str) -> str:
        require_text(password, "password")
        if bcrypt is not None:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return f"scrypt${salt.hex()}${digest.hex()}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        if password_hash.startswith("$2") and bcrypt is not None:
            return bool(bcrypt.checkpw(password.encode(), password_hash.encode()))
        if password_hash.startswith("scrypt$"):
            _, salt_hex, digest_hex = password_hash.split("$", 2)
            candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1)
            return hmac.compare_digest(candidate.hex(), digest_hex)
        return False

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def create_user(self, username: str | None, display_name: str | None = None, password: str | None = None, email: str | None = None, actor_id: UUID | None = None) -> dict[str, str | bool]:
        username = require_text(username, "username")
        if password is None and email is None:
            display_name = require_text(display_name, "display_name")
            user_id = uuid4()
            try:
                self._execute("INSERT INTO users VALUES (%s, %s, %s)", (user_id, username, display_name))
            except Exception as error:
                if "unique" in str(error).lower():
                    raise conflict("username already exists") from error
                raise
            return {"id": str(user_id), "username": username, "display_name": display_name}
        email = require_text(email, "email")
        password = require_text(password, "password")
        display_name = require_text(display_name or username, "display_name")
        user_id = uuid4()
        try:
            self._execute("INSERT INTO users (id, username, email, display_name, password_hash, is_active) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, username, email, display_name, self.hash_password(password), True))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("username or email already exists") from error
            raise
        self._audit(actor_id, "USER_CREATED", "user", user_id, "success")
        return {"id": str(user_id), "username": username, "email": email, "display_name": display_name, "is_active": True}

    def get_user(self, user_id: UUID) -> dict[str, str | bool]:
        row = self._one("SELECT id, username, display_name FROM users WHERE id = %s", (user_id,))
        if row is None:
            raise not_found("user not found")
        return {"id": str(row[0]), "username": row[1], "display_name": row[2]}

    def update_user(self, user_id: UUID, display_name: str | None = None, email: str | None = None, is_active: bool | None = None, actor_id: UUID | None = None) -> dict[str, str | bool]:
        self._require_reference("users", user_id, "user")
        fields: list[str] = []
        values: list[SqlParameter] = []
        if display_name is not None:
            fields.append("display_name = %s")
            values.append(require_text(display_name, "display_name"))
        if email is not None:
            fields.append("email = %s")
            values.append(require_text(email, "email"))
        if is_active is not None:
            fields.append("is_active = %s")
            values.append(is_active)
        if not fields:
            raise ValueError("at least one user field is required")
        try:
            self._execute(f"UPDATE users SET {', '.join(fields)} WHERE id = %s", tuple(values) + (user_id,))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("email already exists") from error
            raise
        self._audit(actor_id, "USER_UPDATED", "user", user_id, "success")
        return self.get_user(user_id)

    def delete_user(self, user_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("users", user_id, "user")
        self._execute("DELETE FROM users WHERE id = %s", (user_id,))
        self._audit(actor_id, "USER_DELETED", "user", user_id, "success")

    def list_users(self) -> list[dict[str, str | bool]]:
        rows = self._all("SELECT id, username, email, display_name, is_active FROM users ORDER BY username")
        return [{"id": str(row[0]), "username": row[1], "email": row[2], "display_name": row[3], "is_active": row[4]} for row in rows]

    def create_group(self, name: str | None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        name = require_text(name, "name")
        group_id = uuid4()
        try:
            try:
                self._execute("INSERT INTO groups (id, name, description) VALUES (%s, %s, %s)", (group_id, name, description or ""))
            except Exception as error:
                if "no column named description" not in str(error).lower():
                    raise
                self._execute("INSERT INTO groups (id, name) VALUES (%s, %s)", (group_id, name))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("group already exists") from error
            raise
        self._audit(actor_id, "GROUP_CREATED", "group", group_id, "success")
        return {"id": str(group_id), "name": name, "description": description or ""}

    def get_group(self, group_id: UUID) -> dict[str, str]:
        row = self._one("SELECT id, name FROM groups WHERE id = %s", (group_id,))
        if row is None:
            raise not_found("group not found")
        return {"id": str(row[0]), "name": row[1]}

    def update_group(self, group_id: UUID, name: str | None = None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        self._require_reference("groups", group_id, "group")
        fields: list[str] = []
        values: list[SqlParameter] = []
        if name is not None:
            fields.append("name = %s")
            values.append(require_text(name, "name"))
        if description is not None:
            fields.append("description = %s")
            values.append(description)
        if not fields:
            raise ValueError("at least one group field is required")
        self._execute(f"UPDATE groups SET {', '.join(fields)} WHERE id = %s", tuple(values) + (group_id,))
        self._audit(actor_id, "GROUP_UPDATED", "group", group_id, "success")
        return self.get_group(group_id)

    def delete_group(self, group_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("groups", group_id, "group")
        self._execute("DELETE FROM groups WHERE id = %s", (group_id,))
        self._audit(actor_id, "GROUP_DELETED", "group", group_id, "success")

    def list_groups(self) -> list[dict[str, str]]:
        rows = self._all("SELECT id, name, description FROM groups ORDER BY name")
        return [{"id": str(row[0]), "name": row[1], "description": row[2]} for row in rows]

    def user_groups(self, user_id: UUID) -> list[dict[str, str]]:
        self._require_reference("users", user_id, "user")
        rows = self._all("SELECT g.id, g.name, g.description FROM groups g JOIN user_groups ug ON ug.group_id = g.id WHERE ug.user_id = %s ORDER BY g.name", (user_id,))
        return [{"id": str(row[0]), "name": row[1], "description": row[2]} for row in rows]

    def create_role(self, name: str | None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        name = require_text(name, "name")
        role_id = uuid4()
        try:
            try:
                self._execute("INSERT INTO roles (id, name, description) VALUES (%s, %s, %s)", (role_id, name, description or ""))
            except Exception as error:
                if "no column named description" not in str(error).lower():
                    raise
                self._execute("INSERT INTO roles (id, name) VALUES (%s, %s)", (role_id, name))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("role already exists") from error
            raise
        self._audit(actor_id, "ROLE_CREATED", "role", role_id, "success")
        return {"id": str(role_id), "name": name, "description": description or ""}

    def get_role(self, role_id: UUID) -> dict[str, str]:
        row = self._one("SELECT id, name FROM roles WHERE id = %s", (role_id,))
        if row is None:
            raise not_found("role not found")
        return {"id": str(row[0]), "name": row[1]}

    def update_role(self, role_id: UUID, name: str | None = None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        self._require_reference("roles", role_id, "role")
        if name == "Administrator":
            raise forbidden("privileged role is protected")
        fields: list[str] = []
        values: list[SqlParameter] = []
        if name is not None:
            fields.append("name = %s")
            values.append(require_text(name, "name"))
        if description is not None:
            fields.append("description = %s")
            values.append(description)
        if not fields:
            raise ValueError("at least one role field is required")
        self._execute(f"UPDATE roles SET {', '.join(fields)} WHERE id = %s", tuple(values) + (role_id,))
        self._audit(actor_id, "ROLE_UPDATED", "role", role_id, "success")
        return self.get_role(role_id)

    def delete_role(self, role_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("roles", role_id, "role")
        protected = self._one("SELECT 1 FROM roles WHERE id = %s AND name = %s", (role_id, "Administrator"))
        if protected is not None:
            raise forbidden("privileged role is protected")
        self._execute("DELETE FROM roles WHERE id = %s", (role_id,))
        self._audit(actor_id, "ROLE_DELETED", "role", role_id, "success")

    def list_roles(self) -> list[dict[str, str]]:
        rows = self._all("SELECT id, name, description FROM roles ORDER BY name")
        return [{"id": str(row[0]), "name": row[1], "description": row[2]} for row in rows]

    def user_roles(self, user_id: UUID) -> list[dict[str, str]]:
        self._require_reference("users", user_id, "user")
        rows = self._all("SELECT r.id, r.name, r.description FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = %s ORDER BY r.name", (user_id,))
        return [{"id": str(row[0]), "name": row[1], "description": row[2]} for row in rows]

    def create_permission(self, resource: str | None, action: str | None, actor_id: UUID | None = None) -> dict[str, str]:
        resource = require_text(resource, "resource")
        action = require_text(action, "action")
        permission_id = uuid4()
        try:
            self._execute("INSERT INTO permissions (id, resource, action) VALUES (%s, %s, %s)", (permission_id, resource, action))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("permission already exists") from error
            raise
        self._audit(actor_id, "PERMISSION_CREATED", "permission", permission_id, "success")
        return {"id": str(permission_id), "resource": resource, "action": action}

    def delete_permission(self, permission_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("permissions", permission_id, "permission")
        self._execute("DELETE FROM permissions WHERE id = %s", (permission_id,))
        self._audit(actor_id, "PERMISSION_DELETED", "permission", permission_id, "success")

    def list_permissions(self) -> list[dict[str, str]]:
        rows = self._all("SELECT id, resource, action FROM permissions ORDER BY resource, action")
        return [{"id": str(row[0]), "resource": row[1], "action": row[2]} for row in rows]

    def get_permission(self, permission_id: UUID) -> dict[str, str]:
        row = self._one("SELECT id, resource, action FROM permissions WHERE id = %s", (permission_id,))
        if row is None:
            raise not_found("permission not found")
        return {"id": str(row[0]), "resource": row[1], "action": row[2]}

    def _require_reference(self, table: str, identifier: UUID, label: str) -> None:
        if self._one(f"SELECT 1 FROM {table} WHERE id = %s", (identifier,)) is None:
            raise not_found(f"{label} not found")

    def _relationship(self, query: str, parameters: tuple[SqlParameter, ...], message: str) -> None:
        try:
            self._execute(query, parameters)
        except Exception as error:
            if "duplicate" in str(error).lower() or "unique" in str(error).lower():
                raise conflict(message) from error
            raise

    def add_user_to_group(self, user_id: UUID, group_id: UUID, actor_id: UUID | None = None) -> dict[str, str]:
        self._require_reference("users", user_id, "user")
        self._require_reference("groups", group_id, "group")
        self._relationship("INSERT INTO user_groups VALUES (%s, %s)", (user_id, group_id), "user is already in group")
        self._audit(actor_id, "USER_ADDED_TO_GROUP", "user", user_id, "success", {"group_id": str(group_id)})
        return {"user_id": str(user_id), "group_id": str(group_id)}

    def remove_user_from_group(self, user_id: UUID, group_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("users", user_id, "user")
        self._require_reference("groups", group_id, "group")
        self._execute("DELETE FROM user_groups WHERE user_id = %s AND group_id = %s", (user_id, group_id))
        self._audit(actor_id, "USER_REMOVED_FROM_GROUP", "user", user_id, "success", {"group_id": str(group_id)})

    def assign_role(self, user_id: UUID, role_id: UUID, actor_id: UUID | None = None) -> dict[str, str]:
        self._require_reference("users", user_id, "user")
        self._require_reference("roles", role_id, "role")
        self._relationship("INSERT INTO user_roles VALUES (%s, %s)", (user_id, role_id), "role is already assigned")
        self._audit(actor_id, "ROLE_ASSIGNED", "user", user_id, "success", {"role_id": str(role_id)})
        return {"user_id": str(user_id), "role_id": str(role_id)}

    def remove_role(self, user_id: UUID, role_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("users", user_id, "user")
        self._require_reference("roles", role_id, "role")
        self._execute("DELETE FROM user_roles WHERE user_id = %s AND role_id = %s", (user_id, role_id))
        self._audit(actor_id, "ROLE_REMOVED", "user", user_id, "success", {"role_id": str(role_id)})

    def assign_permission(self, role_id: UUID, permission_id: UUID, actor_id: UUID | None = None) -> dict[str, str]:
        self._require_reference("roles", role_id, "role")
        self._require_reference("permissions", permission_id, "permission")
        self._relationship("INSERT INTO role_permissions VALUES (%s, %s)", (role_id, permission_id), "permission is already assigned")
        self._audit(actor_id, "PERMISSION_ASSIGNED", "role", role_id, "success", {"permission_id": str(permission_id)})
        return {"role_id": str(role_id), "permission_id": str(permission_id)}

    def remove_permission(self, role_id: UUID, permission_id: UUID, actor_id: UUID | None = None) -> None:
        self._require_reference("roles", role_id, "role")
        self._require_reference("permissions", permission_id, "permission")
        self._execute("DELETE FROM role_permissions WHERE role_id = %s AND permission_id = %s", (role_id, permission_id))
        self._audit(actor_id, "PERMISSION_REMOVED", "role", role_id, "success", {"permission_id": str(permission_id)})

    def role_permissions(self, role_id: UUID) -> list[dict[str, str]]:
        self._require_reference("roles", role_id, "role")
        rows = self._all("SELECT p.id, p.resource, p.action FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id WHERE rp.role_id = %s ORDER BY p.resource, p.action", (role_id,))
        return [{"id": str(row[0]), "resource": row[1], "action": row[2]} for row in rows]

    def user_permissions(self, user_id: UUID) -> list[dict[str, str]]:
        self._require_reference("users", user_id, "user")
        rows = self._all("SELECT DISTINCT p.id, p.resource, p.action FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id JOIN user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = %s ORDER BY p.resource, p.action", (user_id,))
        return [{"id": str(row[0]), "resource": row[1], "action": row[2]} for row in rows]

    def check_permission(self, user_id: UUID, resource: str, action: str) -> bool:
        resource = require_text(resource, "resource")
        action = require_text(action, "action")
        return any(item["resource"] == resource and item["action"] == action for item in self.user_permissions(user_id))

    def create_application(self, name: str | None, description: str | None, actor_id: UUID) -> dict[str, str]:
        name = require_text(name, "name")
        description = description or ""
        application_id = uuid4()
        try:
            self._execute("INSERT INTO applications (id, name, description) VALUES (%s, %s, %s)", (application_id, name, description))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("application already exists") from error
            raise
        self._audit(actor_id, "APPLICATION_CREATED", "application", application_id, "success")
        return {"id": str(application_id), "name": name, "description": description}

    def list_applications(self) -> list[dict[str, str]]:
        rows = self._all("SELECT id, name, description FROM applications ORDER BY name")
        return [{"id": str(row[0]), "name": row[1], "description": row[2]} for row in rows]

    def get_application(self, application_id: UUID) -> dict[str, str]:
        row = self._one("SELECT id, name, description FROM applications WHERE id = %s", (application_id,))
        if row is None:
            raise not_found("application not found")
        return {"id": str(row[0]), "name": row[1], "description": row[2]}

    def update_application(self, application_id: UUID, name: str | None, description: str | None, actor_id: UUID) -> dict[str, str]:
        self._require_reference("applications", application_id, "application")
        fields: list[str] = []
        values: list[SqlParameter] = []
        if name is not None:
            fields.append("name = %s")
            values.append(require_text(name, "name"))
        if description is not None:
            fields.append("description = %s")
            values.append(description)
        if not fields:
            raise ValueError("at least one application field is required")
        try:
            self._execute(f"UPDATE applications SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s", tuple(values) + (application_id,))
        except Exception as error:
            if "unique" in str(error).lower():
                raise conflict("application already exists") from error
            raise
        self._audit(actor_id, "APPLICATION_UPDATED", "application", application_id, "success")
        return self.get_application(application_id)

    def delete_application(self, application_id: UUID, actor_id: UUID) -> None:
        self._require_reference("applications", application_id, "application")
        self._execute("DELETE FROM applications WHERE id = %s", (application_id,))
        self._audit(actor_id, "APPLICATION_DELETED", "application", application_id, "success")

    def deploy_application(self, application_id: UUID, actor_id: UUID) -> dict[str, str]:
        self._require_reference("applications", application_id, "application")
        self._audit(actor_id, "APPLICATION_DEPLOYED", "application", application_id, "success")
        return {"status": "deployed", "application_id": str(application_id)}

    def audit_events(self) -> list[dict[str, object]]:
        rows = self._all("SELECT id, timestamp, event_type, user_id, target_type, target_id, result, metadata FROM audit_events ORDER BY id DESC")
        return [{"id": row[0], "timestamp": row[1], "event_type": row[2], "user_id": str(row[3]) if row[3] else None, "target_type": row[4], "target_id": str(row[5]) if row[5] else None, "result": row[6], "metadata": row[7]} for row in rows]

    def authorize(self, user_id: UUID, resource: str, action: str, target_id: UUID | None = None) -> None:
        allowed = self.check_permission(user_id, resource, action)
        event = "AUTHORIZATION_ALLOWED" if allowed else "AUTHORIZATION_DENIED"
        self._audit(user_id, event, resource, target_id, "success" if allowed else "denied", {"action": action})
        if not allowed:
            raise forbidden()

    def login(self, username: str | None, password: str | None) -> dict[str, str]:
        username = require_text(username, "username")
        password = require_text(password, "password")
        row = self._one("SELECT id, password_hash, is_active, locked_until, failed_login_count FROM users WHERE username = %s", (username,))
        if row is not None and row[3] is not None and row[3] > self._now():
            self._audit(None, "LOGIN_FAILURE", "user", row[0], "denied")
            raise too_many_requests()
        valid = row is not None and bool(row[2]) and (row[3] is None or row[3] <= self._now()) and self.verify_password(password, str(row[1]))
        if not valid:
            if row is not None:
                self._record_login_failure(row[0], int(row[4]) + 1)
            self._audit(None, "LOGIN_FAILURE", "user", row[0] if row else None, "denied")
            raise unauthorized("invalid username or password")
        session_id = secrets.token_urlsafe(32)
        expires_at = self._now() + SESSION_LIFETIME
        self._execute("INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (%s, %s, %s, %s)", (session_id, row[0], self._now(), expires_at))
        self._audit(row[0], "LOGIN_SUCCESS", "user", row[0], "success")
        return {"session_id": session_id, "user_id": str(row[0]), "expires_at": expires_at.isoformat()}

    def _record_login_failure(self, user_id: UUID, failure_count: int) -> None:
        lock_until = self._now() + timedelta(minutes=15) if failure_count >= 5 else None
        self._execute("UPDATE users SET failed_login_count = %s, locked_until = %s, updated_at = %s WHERE id = %s", (failure_count, lock_until, self._now(), user_id))

    def bootstrap(self, username: str | None, password: str | None, email: str | None) -> None:
        username = require_text(username, "BOOTSTRAP_ADMIN_USERNAME")
        password = require_text(password, "BOOTSTRAP_ADMIN_PASSWORD")
        email = require_text(email, "BOOTSTRAP_ADMIN_EMAIL")
        existing = self._one("SELECT id FROM roles WHERE name = %s", ("Administrator",))
        role_id = UUID(str(existing[0])) if existing else UUID(str(self.create_role("Administrator", "Bootstrap administrator")["id"]))
        permission = self._one("SELECT id FROM permissions WHERE resource = %s AND action = %s", ("iam", "manage"))
        permission_id = UUID(str(permission[0])) if permission else UUID(str(self.create_permission("iam", "manage")["id"]))
        if self._one("SELECT 1 FROM role_permissions WHERE role_id = %s AND permission_id = %s", (role_id, permission_id)) is None:
            self._relationship("INSERT INTO role_permissions VALUES (%s, %s)", (role_id, permission_id), "permission is already assigned")
        user = self._one("SELECT id FROM users WHERE username = %s", (username,))
        user_id = UUID(str(user[0])) if user else UUID(str(self.create_user(username, username, password, email)["id"]))
        if self._one("SELECT 1 FROM user_roles WHERE user_id = %s AND role_id = %s", (user_id, role_id)) is None:
            self._relationship("INSERT INTO user_roles VALUES (%s, %s)", (user_id, role_id), "role is already assigned")

    def authenticate(self, session_id: str | None) -> UUID:
        if not session_id:
            raise unauthorized()
        row = self._one("SELECT s.user_id, s.expires_at, s.revoked_at, u.is_active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = %s", (session_id,))
        if row is None or row[2] is not None or row[1] <= self._now() or not row[3]:
            raise unauthorized()
        return UUID(str(row[0]))

    def logout(self, session_id: str | None, actor_id: UUID) -> None:
        if session_id:
            self._execute("UPDATE sessions SET revoked_at = %s WHERE id = %s AND revoked_at IS NULL", (self._now(), session_id))
        self._audit(actor_id, "LOGOUT", "session", None, "success")
        self._audit(actor_id, "SESSION_REVOKED", "session", None, "success")

    def _audit(self, user_id: UUID | None, event_type: str, target_type: str, target_id: UUID | None, result: str, metadata: dict[str, str] | None = None) -> None:
        try:
            self._execute("INSERT INTO audit_events (timestamp, event_type, user_id, target_type, target_id, result, metadata) VALUES (%s, %s, %s, %s, %s, %s, %s)", (self._now(), event_type, user_id, target_type, target_id, result, str(metadata or {})))
        except Exception as error:
            if "no such table" not in str(error).lower() and "undefined table" not in str(error).lower():
                raise
