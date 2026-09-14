from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

from ..core.errors import conflict, not_found
from ..core.validation import require_text
from .ports import SqlParameter


class ApplicationManager:
    """Protected application resource operations behind the V1 service facade."""

    def __init__(self, one: Callable[..., Any], execute: Callable[..., None], audit: Callable[..., None]):
        self._one = one
        self._execute = execute
        self._audit = audit

    def _require_reference(self, application_id: UUID) -> None:
        if self._one("SELECT 1 FROM applications WHERE id = %s", (application_id,)) is None:
            raise not_found("application not found")

    def create(self, name: str | None, description: str | None, actor_id: UUID) -> dict[str, str]:
        name = require_text(name, "name")
        application_id = uuid4()
        try:
            self._execute(
                "INSERT INTO applications (id, name, description) VALUES (%s, %s, %s)",
                (application_id, name, description or ""),
            )
        except Exception as error:
            if getattr(error, "sqlstate", None) == "23505" or error.__class__.__name__ == "IntegrityError":
                raise conflict("application already exists") from error
            raise
        self._audit(actor_id, "APPLICATION_CREATED", "application", application_id, "success")
        return {"id": str(application_id), "name": name, "description": description or ""}

    def list(self, all_rows: Callable[..., list[Any]]) -> list[dict[str, str]]:
        rows = all_rows("SELECT id, name, description FROM applications ORDER BY name")
        return [{"id": str(row[0]), "name": row[1], "description": row[2]} for row in rows]

    def get(self, application_id: UUID) -> dict[str, str]:
        row = self._one("SELECT id, name, description FROM applications WHERE id = %s", (application_id,))
        if row is None:
            raise not_found("application not found")
        return {"id": str(row[0]), "name": row[1], "description": row[2]}

    def update(self, application_id: UUID, name: str | None, description: str | None, actor_id: UUID) -> dict[str, str]:
        self._require_reference(application_id)
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
            self._execute(
                f"UPDATE applications SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                tuple(values) + (application_id,),
            )
        except Exception as error:
            if getattr(error, "sqlstate", None) == "23505" or error.__class__.__name__ == "IntegrityError":
                raise conflict("application already exists") from error
            raise
        self._audit(actor_id, "APPLICATION_UPDATED", "application", application_id, "success")
        return self.get(application_id)

    def delete(self, application_id: UUID, actor_id: UUID) -> None:
        self._require_reference(application_id)
        self._execute("DELETE FROM applications WHERE id = %s", (application_id,))
        self._audit(actor_id, "APPLICATION_DELETED", "application", application_id, "success")

    def deploy(self, application_id: UUID, actor_id: UUID) -> dict[str, str]:
        self._require_reference(application_id)
        self._audit(actor_id, "APPLICATION_DEPLOYED", "application", application_id, "success")
        return {"status": "deployed", "application_id": str(application_id)}
