import os
import shutil
import subprocess


CONTAINER_NAME = "iam-postgres"


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required when IAM_AUTO_START_POSTGRES=true")
    return value


def auto_start_postgres() -> None:
    """Start the local development PostgreSQL container when explicitly enabled."""

    if os.environ.get("IAM_AUTO_START_POSTGRES", "false").lower() != "true":
        return

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError(
            "IAM_AUTO_START_POSTGRES is enabled, but Docker was not found. "
            "Install Docker Desktop or disable IAM_AUTO_START_POSTGRES."
        )

    container_exists = subprocess.run(
        [docker, "container", "inspect", CONTAINER_NAME],
        capture_output=True,
        check=False,
        text=True,
    ).returncode == 0

    if container_exists:
        subprocess.run([docker, "start", CONTAINER_NAME], check=True)
        return

    subprocess.run(
        [
            docker,
            "run",
            "--name",
            CONTAINER_NAME,
            "-e",
            f"POSTGRES_USER={_required_environment('POSTGRES_USER')}",
            "-e",
            f"POSTGRES_PASSWORD={_required_environment('POSTGRES_PASSWORD')}",
            "-e",
            f"POSTGRES_DB={_required_environment('POSTGRES_DB')}",
            "-p",
            "5432:5432",
            "-d",
            "postgres:16",
        ],
        check=True,
    )
