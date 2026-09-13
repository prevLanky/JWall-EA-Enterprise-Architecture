from collections.abc import Callable
from contextlib import AbstractContextManager
from types import TracebackType
from typing import Any, Protocol, TypedDict
from uuid import UUID


SqlParameter = UUID | str | None
SqlRow = tuple[Any, ...]
ConnectionFactory = Callable[[], AbstractContextManager["Connection"]]


class Cursor(Protocol):
    def __enter__(self) -> "Cursor": ...
    def __exit__(self, exception_type: type[BaseException] | None, exception: BaseException | None, traceback: TracebackType | None) -> bool | None: ...
    def execute(self, query: str, parameters: tuple[SqlParameter, ...] = ()) -> None: ...
    def fetchone(self) -> SqlRow | None: ...
    def fetchall(self) -> list[SqlRow]: ...


class Connection(Protocol):
    def __enter__(self) -> "Connection": ...
    def __exit__(self, exception_type: type[BaseException] | None, exception: BaseException | None, traceback: TracebackType | None) -> bool | None: ...
    def cursor(self) -> Cursor: ...
    def commit(self) -> None: ...


class UserResult(TypedDict):
    id: str
    username: str
    display_name: str


class NamedResult(TypedDict):
    id: str
    name: str


class PermissionResult(TypedDict):
    id: str
    resource: str
    action: str


class RelationshipResult(TypedDict):
    user_id: str
    group_id: str


class RoleAssignmentResult(TypedDict):
    user_id: str
    role_id: str


class PermissionAssignmentResult(TypedDict):
    role_id: str
    permission_id: str


__all__ = [
    "Connection",
    "ConnectionFactory",
    "Cursor",
    "PermissionAssignmentResult",
    "PermissionResult",
    "RelationshipResult",
    "RoleAssignmentResult",
    "SqlParameter",
    "SqlRow",
    "UserResult",
    "NamedResult",
]
