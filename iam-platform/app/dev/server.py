"""Development launcher: reset once, then reload without resetting the database."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from ..infrastructure.database import prepare_database
from ..infrastructure.runtime import auto_start_postgres


def _load_local_environment() -> None:
    environment_file = Path(__file__).resolve().parents[2] / ".env"
    if not environment_file.exists():
        return
    for line in environment_file.read_text(encoding="utf-8").splitlines():
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#") or "=" not in stripped_line:
            continue
        name, value = stripped_line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


def main() -> None:
    _load_local_environment()
    auto_start_postgres()
    prepare_database(reset=True)
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("IAM_HOST", "127.0.0.1"),
        port=int(os.environ.get("IAM_PORT", "8002")),
        reload=True,
        reload_dirs=[Path(__file__).resolve().parent.parent],
    )


if __name__ == "__main__":
    main()
