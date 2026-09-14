from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID


class AuditWriter:
    """Trusted server-side audit boundary for security-relevant events."""

    def __init__(self, execute: Callable[..., None], now: Callable[[], Any]):
        self._execute = execute
        self._now = now

    def record(
        self,
        user_id: UUID | None,
        event_type: str,
        target_type: str,
        target_id: UUID | None,
        result: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        self._execute(
            "INSERT INTO audit_events (timestamp, event_type, user_id, target_type, target_id, result, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (self._now(), event_type, user_id, target_type, target_id, result, str(metadata or {})),
        )
