from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .api.routes import create_router
from .domain.iam import IamService


StartupAction = Callable[[], None]

__all__ = ["StartupAction", "create_app"]


def create_app(service: IamService, startup_action: StartupAction | None = None) -> FastAPI:
    """Build an IAM API that can be mounted into a larger FastAPI application."""

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        if startup_action is not None:
            startup_action()
        yield

    application = FastAPI(title="IAM Platform", lifespan=lifespan)

    @application.exception_handler(Exception)
    async def unexpected_error_handler(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    application.include_router(create_router(service))

    @application.get("/")
    def root() -> dict[str, str]:
        return {
            "name": "IAM Platform",
            "docs": "/docs",
            "openapi": "/openapi.json",
            "health": "/health",
        }

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return application
