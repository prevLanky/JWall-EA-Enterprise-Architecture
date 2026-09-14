from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

from ..core.errors import conflict, forbidden, not_found
from ..core.validation import require_password, require_text
from .ports import SqlParameter


def _is_unique_violation(error: BaseException) -> bool:
    return getattr(error, "sqlstate", None) == "23505" or error.__class__.__name__ == "IntegrityError"


class IdentityManager:
    """User, group, role, permission, and relationship lifecycle operations."""

    def __init__(self, one: Callable[..., object], all_rows: Callable[..., list[tuple]], execute: Callable[..., None], audit: Callable[..., None], hash_password: Callable[[str], str]):
        self._one = one
        self._all = all_rows
        self._execute = execute
        self._audit = audit
        self._hash_password = hash_password

    def _require_reference(self, table: str, identifier: UUID, label: str) -> None:
        if self._one(f"SELECT 1 FROM {table} WHERE id = %s", (identifier,)) is None:
            raise not_found(f"{label} not found")

    def _relationship(self, query: str, parameters: tuple[SqlParameter, ...], message: str) -> None:
        try:
            self._execute(query, parameters)
        except Exception as error:
            if _is_unique_violation(error):
                raise conflict(message) from error
            raise

    def create_user(self, username: str | None, display_name: str | None = None, password: str | None = None, email: str | None = None, actor_id: UUID | None = None) -> dict[str, str | bool]:
        username = require_text(username, "username")
        if password is None and email is None:
            display_name = require_text(display_name, "display_name")
            user_id = uuid4()
            try:
                self._execute("INSERT INTO users (id, username, display_name) VALUES (%s, %s, %s)", (user_id, username, display_name))
            except Exception as error:
                if _is_unique_violation(error):
                    raise conflict("username already exists") from error
                raise
            return {"id": str(user_id), "username": username, "display_name": display_name}
        email = require_text(email, "email")
        password = require_password(password)
        display_name = require_text(display_name or username, "display_name")
        user_id = uuid4()
        try:
            self._execute("INSERT INTO users (id, username, email, display_name, password_hash, is_active) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, username, email, display_name, self._hash_password(password), True))
        except Exception as error:
            if _is_unique_violation(error):
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
            if _is_unique_violation(error):
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
            self._execute("INSERT INTO groups (id, name, description) VALUES (%s, %s, %s)", (group_id, name, description or ""))
        except Exception as error:
            if _is_unique_violation(error):
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
            self._execute("INSERT INTO roles (id, name, description) VALUES (%s, %s, %s)", (role_id, name, description or ""))
        except Exception as error:
            if _is_unique_violation(error):
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
        existing = self._one("SELECT name FROM roles WHERE id = %s", (role_id,))
        if (existing is not None and existing[0] == "Administrator") or name == "Administrator":
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
            if _is_unique_violation(error):
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
