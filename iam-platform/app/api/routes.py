from collections.abc import Callable
from typing import Any, TypeVar
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import APIKeyHeader

from ..core.errors import IamError
from ..domain.iam import IamService
from .models import (
    ApplicationCreateRequest,
    ApplicationUpdateRequest,
    LoginRequest,
    NamedResourceRequest,
    PasswordChangeRequest,
    PasswordResetCompleteRequest,
    PasswordResetRequest,
    PermissionCreateRequest,
    ResourceUpdateRequest,
    TotpCodeRequest,
    TotpDisableRequest,
    TotpEnrollRequest,
    UserCreateRequest,
    UserUpdateRequest,
)

Result = TypeVar("Result")

session_header = APIKeyHeader(name="X-Session-ID", auto_error=False)


def _call(operation: Callable[[], Result]) -> Result:
    try:
        return operation()
    except IamError as error:
        raise HTTPException(status_code=int(error.status), detail=str(error)) from error


def _actor(service: IamService, session_id: str | None) -> UUID:
    return _call(lambda: service.authenticate(session_id))


def _admin(service: IamService, session_id: str | None) -> UUID:
    user_id = _actor(service, session_id)
    _call(lambda: service.authorize(user_id, "iam", "manage"))
    return user_id


def _application_actor(service: IamService, session_id: str | None, action: str, target_id: UUID | None = None) -> UUID:
    user_id = _actor(service, session_id)
    _call(lambda: service.authorize(user_id, "application", action, target_id))
    return user_id


def _register_auth_routes(router: APIRouter, service: IamService) -> None:
    @router.post("/auth/login")
    def login(payload: LoginRequest) -> dict[str, str]:
        return _call(lambda: service.login(payload.username, payload.password, payload.totp_code))

    @router.post("/auth/logout", status_code=204)
    def logout(response: Response, x_session_id: str | None = Depends(session_header)) -> None:
        user_id = _actor(service, x_session_id)
        _call(lambda: service.logout(x_session_id, user_id))
        response.status_code = 204

    @router.get("/auth/session")
    def session(x_session_id: str | None = Depends(session_header)) -> dict[str, str]:
        return {"user_id": str(_actor(service, x_session_id))}

    @router.get("/auth/sessions")
    def sessions(x_session_id: str | None = Depends(session_header)) -> Any:
        user_id = _actor(service, x_session_id)
        return _call(lambda: service.list_sessions(user_id))

    @router.post("/auth/sessions/revoke-all", status_code=204)
    def revoke_all_sessions(response: Response, x_session_id: str | None = Depends(session_header)) -> None:
        user_id = _actor(service, x_session_id)
        _call(lambda: service.revoke_all_sessions(user_id))
        response.status_code = 204

    @router.post("/auth/password", status_code=204)
    def change_password(payload: PasswordChangeRequest, response: Response, x_session_id: str | None = Depends(session_header)) -> None:
        user_id = _actor(service, x_session_id)
        _call(lambda: service.change_password(user_id, payload.current_password, payload.new_password))
        response.status_code = 204

    @router.post("/auth/password-reset/request", status_code=202)
    def request_password_reset(payload: PasswordResetRequest) -> dict[str, str]:
        _call(lambda: service.request_password_reset(payload.email))
        return {"detail": "If the account exists, reset instructions will be sent."}

    @router.post("/auth/password-reset/complete", status_code=204)
    def complete_password_reset(payload: PasswordResetCompleteRequest, response: Response) -> None:
        _call(lambda: service.complete_password_reset(payload.token, payload.new_password))
        response.status_code = 204

    @router.post("/auth/mfa/totp/enroll")
    def enroll_totp(payload: TotpEnrollRequest, x_session_id: str | None = Depends(session_header)) -> dict[str, str]:
        user_id = _actor(service, x_session_id)
        return _call(lambda: service.enroll_totp(user_id, payload.current_password))

    @router.post("/auth/mfa/totp/verify", status_code=204)
    def verify_totp(payload: TotpCodeRequest, response: Response, x_session_id: str | None = Depends(session_header)) -> None:
        user_id = _actor(service, x_session_id)
        _call(lambda: service.verify_totp_enrollment(user_id, payload.code))
        response.status_code = 204

    @router.get("/auth/mfa")
    def mfa_status(x_session_id: str | None = Depends(session_header)) -> dict[str, bool]:
        user_id = _actor(service, x_session_id)
        return _call(lambda: service.totp_status(user_id))

    @router.delete("/auth/mfa/totp", status_code=204)
    def disable_totp(payload: TotpDisableRequest, response: Response, x_session_id: str | None = Depends(session_header)) -> None:
        user_id = _actor(service, x_session_id)
        _call(lambda: service.disable_totp(user_id, payload.current_password, payload.code))
        response.status_code = 204


def _register_user_routes(router: APIRouter, service: IamService) -> None:
    @router.post("/users", status_code=201)
    def create_user(payload: UserCreateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.create_user(payload.username, payload.display_name, payload.password, payload.email, actor_id))

    @router.get("/users")
    def list_users(x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(service.list_users)

    @router.get("/users/{user_id}")
    def get_user(user_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.get_user(user_id))

    @router.patch("/users/{user_id}")
    def update_user(user_id: UUID, payload: UserUpdateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.update_user(user_id, payload.display_name, payload.email, payload.is_active, actor_id))

    @router.delete("/users/{user_id}", status_code=204)
    def delete_user(user_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.delete_user(user_id, actor_id))

    @router.get("/users/{user_id}/groups")
    def user_groups(user_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.user_groups(user_id))

    @router.get("/users/{user_id}/roles")
    def user_roles(user_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.user_roles(user_id))

    @router.get("/users/{user_id}/permissions")
    def user_permissions(user_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.user_permissions(user_id))

    @router.get("/users/{user_id}/permissions/{resource}/{action}")
    def check_permission(user_id: UUID, resource: str, action: str, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: {"allowed": service.check_permission(user_id, resource, action)})

    @router.post("/users/{user_id}/groups/{group_id}", status_code=201)
    def add_group(user_id: UUID, group_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.add_user_to_group(user_id, group_id, actor_id))

    @router.delete("/users/{user_id}/groups/{group_id}", status_code=204)
    def remove_group(user_id: UUID, group_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.remove_user_from_group(user_id, group_id, actor_id))

    @router.post("/users/{user_id}/roles/{role_id}", status_code=201)
    def assign_role(user_id: UUID, role_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.assign_role(user_id, role_id, actor_id))

    @router.delete("/users/{user_id}/roles/{role_id}", status_code=204)
    def remove_role(user_id: UUID, role_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.remove_role(user_id, role_id, actor_id))


def _register_group_routes(router: APIRouter, service: IamService) -> None:
    @router.post("/groups", status_code=201)
    def create_group(payload: NamedResourceRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.create_group(payload.name, payload.description, actor_id))

    @router.get("/groups")
    def list_groups(x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(service.list_groups)

    @router.get("/groups/{group_id}")
    def get_group(group_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.get_group(group_id))

    @router.patch("/groups/{group_id}")
    def update_group(group_id: UUID, payload: ResourceUpdateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        if payload.name is None and payload.description is None:
            raise HTTPException(status_code=400, detail="name or description is required")
        return _call(lambda: service.update_group(group_id, payload.name, payload.description, actor_id))

    @router.delete("/groups/{group_id}", status_code=204)
    def delete_group(group_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.delete_group(group_id, actor_id))


def _register_role_routes(router: APIRouter, service: IamService) -> None:
    @router.post("/roles", status_code=201)
    def create_role(payload: NamedResourceRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.create_role(payload.name, payload.description, actor_id))

    @router.get("/roles")
    def list_roles(x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(service.list_roles)

    @router.get("/roles/{role_id}")
    def get_role(role_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.get_role(role_id))

    @router.patch("/roles/{role_id}")
    def update_role(role_id: UUID, payload: ResourceUpdateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        if payload.name is None and payload.description is None:
            raise HTTPException(status_code=400, detail="name or description is required")
        return _call(lambda: service.update_role(role_id, payload.name, payload.description, actor_id))

    @router.delete("/roles/{role_id}", status_code=204)
    def delete_role(role_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.delete_role(role_id, actor_id))

    @router.get("/roles/{role_id}/permissions")
    def role_permissions(role_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.role_permissions(role_id))

    @router.post("/roles/{role_id}/permissions/{permission_id}", status_code=201)
    def assign_permission(role_id: UUID, permission_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.assign_permission(role_id, permission_id, actor_id))

    @router.delete("/roles/{role_id}/permissions/{permission_id}", status_code=204)
    def remove_permission(role_id: UUID, permission_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.remove_permission(role_id, permission_id, actor_id))


def _register_permission_routes(router: APIRouter, service: IamService) -> None:
    @router.post("/permissions", status_code=201)
    def create_permission(payload: PermissionCreateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _admin(service, x_session_id)
        return _call(lambda: service.create_permission(payload.resource, payload.action, actor_id))

    @router.get("/permissions")
    def list_permissions(x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(service.list_permissions)

    @router.get("/permissions/{permission_id}")
    def get_permission(permission_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(lambda: service.get_permission(permission_id))

    @router.delete("/permissions/{permission_id}", status_code=204)
    def delete_permission(permission_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _admin(service, x_session_id)
        _call(lambda: service.delete_permission(permission_id, actor_id))


def _register_application_routes(router: APIRouter, service: IamService) -> None:
    @router.post("/applications", status_code=201)
    def create_application(payload: ApplicationCreateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _application_actor(service, x_session_id, "create")
        return _call(lambda: service.create_application(payload.name, payload.description, actor_id))

    @router.get("/applications")
    def list_applications(x_session_id: str | None = Depends(session_header)) -> Any:
        _application_actor(service, x_session_id, "read")
        return _call(service.list_applications)

    @router.get("/applications/{application_id}")
    def get_application(application_id: UUID, x_session_id: str | None = Depends(session_header)) -> Any:
        _application_actor(service, x_session_id, "read", application_id)
        return _call(lambda: service.get_application(application_id))

    @router.patch("/applications/{application_id}")
    def update_application(application_id: UUID, payload: ApplicationUpdateRequest, x_session_id: str | None = Depends(session_header)) -> Any:
        actor_id = _application_actor(service, x_session_id, "update", application_id)
        if payload.name is None and payload.description is None:
            raise HTTPException(status_code=400, detail="name or description is required")
        return _call(lambda: service.update_application(application_id, payload.name, payload.description, actor_id))

    @router.delete("/applications/{application_id}", status_code=204)
    def delete_application(application_id: UUID, x_session_id: str | None = Depends(session_header)) -> None:
        actor_id = _application_actor(service, x_session_id, "delete", application_id)
        _call(lambda: service.delete_application(application_id, actor_id))

    @router.post("/applications/{application_id}/deploy")
    def deploy_application(application_id: UUID, x_session_id: str | None = Depends(session_header)) -> dict[str, str]:
        actor_id = _application_actor(service, x_session_id, "deploy", application_id)
        return _call(lambda: service.deploy_application(application_id, actor_id))


def _register_audit_routes(router: APIRouter, service: IamService) -> None:
    @router.get("/audit")
    def audit_events(x_session_id: str | None = Depends(session_header)) -> Any:
        _admin(service, x_session_id)
        return _call(service.audit_events)


def create_router(service: IamService) -> APIRouter:
    router = APIRouter()
    _register_auth_routes(router, service)
    _register_user_routes(router, service)
    _register_group_routes(router, service)
    _register_role_routes(router, service)
    _register_permission_routes(router, service)
    _register_application_routes(router, service)
    _register_audit_routes(router, service)
    return router


__all__ = ["create_router"]
