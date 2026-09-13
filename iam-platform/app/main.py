from fastapi import FastAPI
import os

if __package__ in (None, ""):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from app.application import create_app
    from app.infrastructure.database import connection, prepare_database
    from app.domain.iam import IamService
    from app.infrastructure.runtime import auto_start_postgres
else:
    from .application import create_app
    from .infrastructure.database import connection, prepare_database
    from .domain.iam import IamService
    from .infrastructure.runtime import auto_start_postgres


def create_default_app() -> FastAPI:
    def startup() -> None:
        auto_start_postgres()
        # Reloads may call startup repeatedly, so this path must never reset persisted data.
        prepare_database(reset=False)
        service = IamService(connection)
        bootstrap_values = (
            os.environ.get("BOOTSTRAP_ADMIN_USERNAME"),
            os.environ.get("BOOTSTRAP_ADMIN_PASSWORD"),
            os.environ.get("BOOTSTRAP_ADMIN_EMAIL"),
        )
        if not all(bootstrap_values):
            raise RuntimeError(
                "Set BOOTSTRAP_ADMIN_USERNAME, BOOTSTRAP_ADMIN_PASSWORD, and "
                "BOOTSTRAP_ADMIN_EMAIL together."
            )
        service.bootstrap(*bootstrap_values)

    return create_app(IamService(connection), startup)


app = create_default_app()


if __name__ == "__main__":
    from app.dev.server import main as start_development_server

    start_development_server()

