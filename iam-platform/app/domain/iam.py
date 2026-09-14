from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from ..core.errors import IamError, conflict, forbidden, not_found, too_many_requests, unauthorized
from ..core.validation import require_password, require_text
from . import authentication
from .audit import AuditWriter
from .applications import ApplicationManager
from .authorization import AuthorizationPolicy
from .identity import IdentityManager
from .secrets import SecretProtectionError, SecretProtector
from .totp import TotpService

PASSWORD_RESET_LIFETIME = timedelta(minutes=30)
TOTP_FAILURE_LIMIT = 5
TOTP_BLOCK_DURATION = timedelta(minutes=15)
from .ports import ConnectionFactory, SqlParameter, SqlRow

__all__ = ["IamService"]

def _is_unique_violation(error: BaseException) -> bool:
    return getattr(error, "sqlstate", None) == "23505" or error.__class__.__name__ == "IntegrityError"


class IamService:
    """Application service containing authentication, RBAC, and audit decisions."""

    def __init__(self, connection_factory: ConnectionFactory):
        self.connection_factory = connection_factory
        self.authorization_policy = AuthorizationPolicy(self.check_permission)
        self.audit_writer = AuditWriter(self._execute, self._now)
        self.application_manager = ApplicationManager(self._one, self._execute, self._audit)
        self.identity_manager = IdentityManager(self._one, self._all, self._execute, self._audit, self.hash_password)

    def _totp_service(self) -> TotpService:
        return TotpService(SecretProtector.from_environment())

    def _verify_totp_with_throttle(self, user_id: UUID, encrypted_secret: str, code: str) -> bool:
        row = self._one("SELECT failed_attempts, blocked_until FROM totp_mfa WHERE user_id = %s", (user_id,))
        if row is not None and row[1] is not None and row[1] > self._now():
            raise too_many_requests("too many MFA attempts")
        try:
            verified = self._totp_service().verify(encrypted_secret.encode("ascii"), code)
        except (SecretProtectionError, UnicodeError):
            verified = False
        if verified:
            self._execute("UPDATE totp_mfa SET failed_attempts = 0, blocked_until = NULL WHERE user_id = %s", (user_id,))
            return True
        block_time = self._now() + TOTP_BLOCK_DURATION
        updated = self._one(
            "UPDATE totp_mfa SET failed_attempts = failed_attempts + 1, "
            "blocked_until = CASE WHEN failed_attempts + 1 >= %s THEN %s ELSE blocked_until END "
            "WHERE user_id = %s RETURNING failed_attempts, blocked_until",
            (TOTP_FAILURE_LIMIT, block_time, user_id),
        )
        failed_attempts = int(updated[0])
        blocked_until = updated[1]
        if blocked_until is not None:
            raise too_many_requests("too many MFA attempts")
        return False

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
        return authentication.hash_password(password)

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        return authentication.verify_password(password, password_hash)

    @staticmethod
    def _now() -> datetime:
        return authentication.now()

    @staticmethod
    def hash_session_id(session_id: str) -> str:
        return authentication.hash_session_id(session_id)

    def create_user(self, username: str | None, display_name: str | None = None, password: str | None = None, email: str | None = None, actor_id: UUID | None = None) -> dict[str, str | bool]:
        return self.identity_manager.create_user(username, display_name, password, email, actor_id)

    def get_user(self, user_id: UUID) -> dict[str, str | bool]:
        return self.identity_manager.get_user(user_id)

    def update_user(self, user_id: UUID, display_name: str | None = None, email: str | None = None, is_active: bool | None = None, actor_id: UUID | None = None) -> dict[str, str | bool]:
        return self.identity_manager.update_user(user_id, display_name, email, is_active, actor_id)

    def delete_user(self, user_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.delete_user(user_id, actor_id)

    def list_users(self) -> list[dict[str, str | bool]]:
        return self.identity_manager.list_users()

    def create_group(self, name: str | None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.create_group(name, description, actor_id)

    def get_group(self, group_id: UUID) -> dict[str, str]:
        return self.identity_manager.get_group(group_id)

    def update_group(self, group_id: UUID, name: str | None = None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.update_group(group_id, name, description, actor_id)

    def delete_group(self, group_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.delete_group(group_id, actor_id)

    def list_groups(self) -> list[dict[str, str]]:
        return self.identity_manager.list_groups()

    def user_groups(self, user_id: UUID) -> list[dict[str, str]]:
        return self.identity_manager.user_groups(user_id)

    def create_role(self, name: str | None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.create_role(name, description, actor_id)

    def get_role(self, role_id: UUID) -> dict[str, str]:
        return self.identity_manager.get_role(role_id)

    def update_role(self, role_id: UUID, name: str | None = None, description: str | None = None, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.update_role(role_id, name, description, actor_id)

    def delete_role(self, role_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.delete_role(role_id, actor_id)

    def list_roles(self) -> list[dict[str, str]]:
        return self.identity_manager.list_roles()

    def user_roles(self, user_id: UUID) -> list[dict[str, str]]:
        return self.identity_manager.user_roles(user_id)

    def create_permission(self, resource: str | None, action: str | None, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.create_permission(resource, action, actor_id)

    def delete_permission(self, permission_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.delete_permission(permission_id, actor_id)

    def list_permissions(self) -> list[dict[str, str]]:
        return self.identity_manager.list_permissions()

    def get_permission(self, permission_id: UUID) -> dict[str, str]:
        return self.identity_manager.get_permission(permission_id)

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

    def add_user_to_group(self, user_id: UUID, group_id: UUID, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.add_user_to_group(user_id, group_id, actor_id)

    def remove_user_from_group(self, user_id: UUID, group_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.remove_user_from_group(user_id, group_id, actor_id)

    def assign_role(self, user_id: UUID, role_id: UUID, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.assign_role(user_id, role_id, actor_id)

    def remove_role(self, user_id: UUID, role_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.remove_role(user_id, role_id, actor_id)

    def assign_permission(self, role_id: UUID, permission_id: UUID, actor_id: UUID | None = None) -> dict[str, str]:
        return self.identity_manager.assign_permission(role_id, permission_id, actor_id)

    def remove_permission(self, role_id: UUID, permission_id: UUID, actor_id: UUID | None = None) -> None:
        self.identity_manager.remove_permission(role_id, permission_id, actor_id)

    def role_permissions(self, role_id: UUID) -> list[dict[str, str]]:
        return self.identity_manager.role_permissions(role_id)

    def user_permissions(self, user_id: UUID) -> list[dict[str, str]]:
        return self.identity_manager.user_permissions(user_id)

    def check_permission(self, user_id: UUID, resource: str, action: str) -> bool:
        return self.identity_manager.check_permission(user_id, resource, action)

    def create_application(self, name: str | None, description: str | None, actor_id: UUID) -> dict[str, str]:
        return self.application_manager.create(name, description, actor_id)

    def list_applications(self) -> list[dict[str, str]]:
        return self.application_manager.list(self._all)

    def get_application(self, application_id: UUID) -> dict[str, str]:
        return self.application_manager.get(application_id)

    def update_application(self, application_id: UUID, name: str | None, description: str | None, actor_id: UUID) -> dict[str, str]:
        return self.application_manager.update(application_id, name, description, actor_id)

    def delete_application(self, application_id: UUID, actor_id: UUID) -> None:
        self.application_manager.delete(application_id, actor_id)

    def deploy_application(self, application_id: UUID, actor_id: UUID) -> dict[str, str]:
        return self.application_manager.deploy(application_id, actor_id)

    def audit_events(self) -> list[dict[str, object]]:
        rows = self._all("SELECT id, timestamp, event_type, user_id, target_type, target_id, result, metadata FROM audit_events ORDER BY id DESC")
        return [{"id": row[0], "timestamp": row[1], "event_type": row[2], "user_id": str(row[3]) if row[3] else None, "target_type": row[4], "target_id": str(row[5]) if row[5] else None, "result": row[6], "metadata": row[7]} for row in rows]

    def authorize(self, user_id: UUID, resource: str, action: str, target_id: UUID | None = None) -> None:
        if target_id is not None and resource == "application":
            if self._one("SELECT 1 FROM applications WHERE id = %s", (target_id,)) is None:
                raise not_found("application not found")
        allowed = self.authorization_policy.permission_checker(user_id, resource, action)
        event = "AUTHORIZATION_ALLOWED" if allowed else "AUTHORIZATION_DENIED"
        self._audit(user_id, event, resource, target_id, "success" if allowed else "denied", {"action": action})
        if not allowed:
            raise forbidden()

    def login(self, username: str | None, password: str | None, totp_code: str | None = None) -> dict[str, str]:
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
        mfa = self._one("SELECT encrypted_secret, enabled FROM totp_mfa WHERE user_id = %s", (row[0],))
        if mfa is not None and mfa[1]:
            try:
                verified = totp_code is not None and self._verify_totp_with_throttle(UUID(str(row[0])), str(mfa[0]), totp_code)
            except IamError:
                self._audit(row[0], "MFA_TOTP_VERIFICATION_FAILED", "user", row[0], "throttled")
                raise
            except (SecretProtectionError, UnicodeError):
                verified = False
            if not verified:
                self._audit(row[0], "MFA_TOTP_VERIFICATION_FAILED", "user", row[0], "denied")
                raise unauthorized("invalid username or password")
            self._audit(row[0], "MFA_TOTP_VERIFICATION_SUCCESS", "user", row[0], "success")
        session_id, expires_at = authentication.new_session()
        self._execute("INSERT INTO sessions (id_hash, user_id, created_at, expires_at) VALUES (%s, %s, %s, %s)", (self.hash_session_id(session_id), row[0], self._now(), expires_at))
        if row[4]:
            self._execute("UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = %s WHERE id = %s", (self._now(), row[0]))
        self._audit(row[0], "LOGIN_SUCCESS", "user", row[0], "success")
        return {"session_id": session_id, "user_id": str(row[0]), "expires_at": expires_at.isoformat()}

    def enroll_totp(self, user_id: UUID, current_password: str) -> dict[str, str]:
        user = self._one("SELECT username, password_hash FROM users WHERE id = %s AND is_active = TRUE", (user_id,))
        if user is None or not self.verify_password(current_password, str(user[1])):
            self._audit(user_id, "MFA_TOTP_ENROLLMENT_FAILED", "user", user_id, "denied")
            raise unauthorized("MFA enrollment is not authorized")
        try:
            encrypted_secret, enrollment = self._totp_service().enroll(str(user[0]))
            now = self._now()
            self._execute(
                "INSERT INTO totp_mfa (user_id, encrypted_secret, enabled, created_at, updated_at) VALUES (%s, %s, FALSE, %s, %s) "
                "ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, enabled = FALSE, updated_at = EXCLUDED.updated_at",
                (user_id, encrypted_secret.decode("ascii"), now, now),
            )
        except SecretProtectionError:
            raise unauthorized("MFA enrollment is unavailable")
        self._audit(user_id, "MFA_TOTP_ENROLLMENT_STARTED", "user", user_id, "success")
        return {"provisioning_uri": enrollment.provisioning_uri}

    def verify_totp_enrollment(self, user_id: UUID, code: str) -> None:
        row = self._one("SELECT encrypted_secret, enabled FROM totp_mfa WHERE user_id = %s", (user_id,))
        if row is None or row[1]:
            raise unauthorized("MFA enrollment is not pending")
        try:
            verified = self._verify_totp_with_throttle(user_id, str(row[0]), code)
        except IamError:
            self._audit(user_id, "MFA_TOTP_ENROLLMENT_FAILED", "user", user_id, "throttled")
            raise
        except (SecretProtectionError, UnicodeError):
            verified = False
        if not verified:
            self._audit(user_id, "MFA_TOTP_ENROLLMENT_FAILED", "user", user_id, "denied")
            raise unauthorized("invalid MFA code")
        self._execute("UPDATE totp_mfa SET enabled = TRUE, last_verified_at = %s, updated_at = %s WHERE user_id = %s", (self._now(), self._now(), user_id))
        self._audit(user_id, "MFA_TOTP_ENROLLMENT_COMPLETED", "user", user_id, "success")

    def totp_status(self, user_id: UUID) -> dict[str, bool]:
        row = self._one("SELECT enabled FROM totp_mfa WHERE user_id = %s", (user_id,))
        return {"enabled": bool(row is not None and row[0])}

    def disable_totp(self, user_id: UUID, current_password: str, code: str) -> None:
        user = self._one("SELECT password_hash FROM users WHERE id = %s AND is_active = TRUE", (user_id,))
        row = self._one("SELECT encrypted_secret, enabled FROM totp_mfa WHERE user_id = %s", (user_id,))
        if user is None or row is None or not row[1] or not self.verify_password(current_password, str(user[0])):
            self._audit(user_id, "MFA_TOTP_DISABLED", "user", user_id, "denied")
            raise unauthorized("MFA disablement is not authorized")
        try:
            verified = self._verify_totp_with_throttle(user_id, str(row[0]), code)
        except IamError:
            self._audit(user_id, "MFA_TOTP_DISABLED", "user", user_id, "throttled")
            raise
        except (SecretProtectionError, UnicodeError):
            verified = False
        if not verified:
            self._audit(user_id, "MFA_TOTP_DISABLED", "user", user_id, "denied")
            raise unauthorized("MFA disablement is not authorized")
        self._execute("DELETE FROM totp_mfa WHERE user_id = %s", (user_id,))
        self._audit(user_id, "MFA_TOTP_DISABLED", "user", user_id, "success")

    def list_sessions(self, user_id: UUID) -> list[dict[str, object]]:
        rows = self._all(
            "SELECT created_at, expires_at, revoked_at FROM sessions WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,),
        )
        return [
            {
                "created_at": row[0].isoformat(),
                "expires_at": row[1].isoformat(),
                "revoked": row[2] is not None,
            }
            for row in rows
        ]

    def revoke_all_sessions(self, user_id: UUID) -> None:
        self._execute(
            "UPDATE sessions SET revoked_at = %s WHERE user_id = %s AND revoked_at IS NULL",
            (self._now(), user_id),
        )
        self._audit(user_id, "SESSIONS_REVOKED_ALL", "user", user_id, "success")

    def change_password(self, user_id: UUID, current_password: str, new_password: str) -> None:
        row = self._one("SELECT password_hash FROM users WHERE id = %s AND is_active = TRUE", (user_id,))
        if row is None or not self.verify_password(current_password, str(row[0])):
            self._audit(user_id, "PASSWORD_CHANGE_FAILURE", "user", user_id, "denied")
            raise unauthorized("current password is invalid")
        new_hash = self.hash_password(new_password)
        self._execute("UPDATE users SET password_hash = %s, updated_at = %s WHERE id = %s", (new_hash, self._now(), user_id))
        self.revoke_all_sessions(user_id)
        self._audit(user_id, "PASSWORD_CHANGED", "user", user_id, "success")

    def issue_password_reset_token(self, email: str) -> str | None:
        row = self._one("SELECT id FROM users WHERE email = %s AND is_active = TRUE", (require_text(email, "email"),))
        if row is None:
            self._audit(None, "PASSWORD_RESET_REQUESTED", "user", None, "accepted")
            return None
        token, expires_at = authentication.new_reset_token(PASSWORD_RESET_LIFETIME)
        self._execute(
            "INSERT INTO password_reset_tokens (token_hash, user_id, created_at, expires_at) VALUES (%s, %s, %s, %s)",
            (self.hash_session_id(token), row[0], self._now(), expires_at),
        )
        self._audit(row[0], "PASSWORD_RESET_REQUESTED", "user", row[0], "accepted")
        return token

    def request_password_reset(self, email: str) -> None:
        # Delivery is intentionally an integration boundary; the API never reveals account existence.
        self.issue_password_reset_token(email)

    def complete_password_reset(self, token: str, new_password: str) -> None:
        row = self._one(
            "SELECT token_hash, user_id FROM password_reset_tokens WHERE token_hash = %s AND used_at IS NULL AND expires_at > %s",
            (self.hash_session_id(token), self._now()),
        )
        if row is None:
            raise unauthorized("password reset token is invalid")
        user_id = UUID(str(row[1]))
        new_hash = self.hash_password(new_password)
        self._execute("UPDATE users SET password_hash = %s, updated_at = %s WHERE id = %s AND is_active = TRUE", (new_hash, self._now(), user_id))
        self._execute("UPDATE password_reset_tokens SET used_at = %s WHERE token_hash = %s", (self._now(), row[0]))
        self.revoke_all_sessions(user_id)
        self._audit(user_id, "PASSWORD_RESET_COMPLETED", "user", user_id, "success")

    def _record_login_failure(self, user_id: UUID, failure_count: int) -> None:
        lock_until = self._now() + timedelta(minutes=15) if failure_count >= 5 else None
        self._execute("UPDATE users SET failed_login_count = %s, locked_until = %s, updated_at = %s WHERE id = %s", (failure_count, lock_until, self._now(), user_id))

    def bootstrap(self, username: str | None, password: str | None, email: str | None) -> None:
        username = require_text(username, "BOOTSTRAP_ADMIN_USERNAME")
        password = require_password(password, "BOOTSTRAP_ADMIN_PASSWORD")
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

    def seed_demo_users(self) -> None:
        """Create repeatable local users for exercising V1 authorization behavior."""
        permissions = {
            action: self._permission_id("application", action)
            for action in ("create", "read", "update", "delete", "deploy")
        }
        role_permissions = {
            "Demo Reader": ("read",),
            "Demo Operator": ("create", "read", "update", "deploy"),
            "Demo Developer": tuple(permissions),
            "Demo Auditor": ("read",),
            "Demo Publisher": ("create", "read", "deploy"),
        }
        for role_name, actions in role_permissions.items():
            role = self._role_id(role_name)
            for action in actions:
                if self._one("SELECT 1 FROM role_permissions WHERE role_id = %s AND permission_id = %s", (role, permissions[action])) is None:
                    self._relationship("INSERT INTO role_permissions VALUES (%s, %s)", (role, permissions[action]), "permission is already assigned")

        demo_users = (
            ("demo-reader", "Demo Reader", "DemoReaderPassword1", "demo-reader@example.test", "Demo Reader"),
            ("demo-operator", "Demo Operator", "DemoOperatorPassword1", "demo-operator@example.test", "Demo Operator"),
            ("demo-developer", "Demo Developer", "DemoDeveloperPassword1", "demo-developer@example.test", "Demo Developer"),
            ("demo-auditor", "Demo Auditor", "DemoAuditorPassword1", "demo-auditor@example.test", "Demo Auditor"),
            ("demo-publisher", "Demo Publisher", "DemoPublisherPassword1", "demo-publisher@example.test", "Demo Publisher"),
        )
        for username, display_name, password, email, role_name in demo_users:
            user = self._one("SELECT id FROM users WHERE username = %s", (username,))
            user_id = UUID(str(user[0])) if user else UUID(str(self.create_user(username, display_name, password, email)["id"]))
            role_id = self._role_id(role_name)
            if self._one("SELECT 1 FROM user_roles WHERE user_id = %s AND role_id = %s", (user_id, role_id)) is None:
                self._relationship("INSERT INTO user_roles VALUES (%s, %s)", (user_id, role_id), "role is already assigned")

        groups = {
            "Platform Observers": ("demo-reader", "demo-auditor"),
            "Release Operators": ("demo-operator", "demo-publisher"),
            "Engineering": ("demo-operator", "demo-developer", "demo-publisher"),
        }
        for group_name, usernames in groups.items():
            group_id = self._group_id(group_name)
            for username in usernames:
                user = self._one("SELECT id FROM users WHERE username = %s", (username,))
                if user is not None and self._one("SELECT 1 FROM user_groups WHERE user_id = %s AND group_id = %s", (user[0], group_id)) is None:
                    self._relationship("INSERT INTO user_groups VALUES (%s, %s)", (user[0], group_id), "user is already in group")

    def _permission_id(self, resource: str, action: str) -> UUID:
        existing = self._one("SELECT id FROM permissions WHERE resource = %s AND action = %s", (resource, action))
        if existing is not None:
            return UUID(str(existing[0]))
        return UUID(str(self.create_permission(resource, action)["id"]))

    def _role_id(self, name: str) -> UUID:
        existing = self._one("SELECT id FROM roles WHERE name = %s", (name,))
        if existing is not None:
            return UUID(str(existing[0]))
        return UUID(str(self.create_role(name, "Local demonstration role")["id"]))

    def _group_id(self, name: str) -> UUID:
        existing = self._one("SELECT id FROM groups WHERE name = %s", (name,))
        if existing is not None:
            return UUID(str(existing[0]))
        return UUID(str(self.create_group(name, "Local demonstration group")["id"]))

    def authenticate(self, session_id: str | None) -> UUID:
        if not session_id or len(session_id) > 512:
            raise unauthorized()
        row = self._one("SELECT s.user_id, s.expires_at, s.revoked_at, u.is_active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = %s", (self.hash_session_id(session_id),))
        if row is None or row[2] is not None or row[1] <= self._now() or not row[3]:
            raise unauthorized()
        return UUID(str(row[0]))

    def logout(self, session_id: str | None, actor_id: UUID) -> None:
        if session_id:
            self._execute("UPDATE sessions SET revoked_at = %s WHERE id_hash = %s AND revoked_at IS NULL", (self._now(), self.hash_session_id(session_id)))
        self._audit(actor_id, "LOGOUT", "session", None, "success")
        self._audit(actor_id, "SESSION_REVOKED", "session", None, "success")

    def _audit(self, user_id: UUID | None, event_type: str, target_type: str, target_id: UUID | None, result: str, metadata: dict[str, str] | None = None) -> None:
        self.audit_writer.record(user_id, event_type, target_type, target_id, result, metadata)
