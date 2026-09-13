from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class User:
    id: UUID
    username: str
    display_name: str


@dataclass(frozen=True)
class Group:
    id: UUID
    name: str


@dataclass(frozen=True)
class Role:
    id: UUID
    name: str


@dataclass(frozen=True)
class Permission:
    id: UUID
    resource: str
    action: str
