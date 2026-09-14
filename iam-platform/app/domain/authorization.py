from __future__ import annotations

from uuid import UUID

from ..core.errors import forbidden


class AuthorizationPolicy:
    """Small in-process authorization policy boundary for subject/resource decisions."""

    def __init__(self, permission_checker):
        self.permission_checker = permission_checker

    def authorize(self, subject_id: UUID, resource: str, action: str, target_id: UUID | None = None) -> None:
        allowed = self.permission_checker(subject_id, resource, action)
        if not allowed:
            raise forbidden()
