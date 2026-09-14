from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import create_router
from .domain.iam import IamService
from .web import ADMIN_PAGE


StartupAction = Callable[[], None]

__all__ = ["StartupAction", "create_app"]

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IAM Platform Login</title>
    <style>
        :root { color-scheme: light; font-family: system-ui, sans-serif; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #eef2f7; color: #172033; }
        main { width: min(92vw, 420px); padding: 2rem; background: white; border: 1px solid #d7dee9; border-radius: 12px; box-shadow: 0 12px 32px #17203318; }
        h1 { margin-top: 0; font-size: 1.6rem; }
        label { display: block; margin: 1rem 0 .35rem; font-weight: 600; }
        input, button { box-sizing: border-box; width: 100%; padding: .7rem .8rem; border-radius: 7px; font: inherit; }
        input { border: 1px solid #aeb9c9; }
        button { margin-top: 1.2rem; border: 0; background: #1f5eff; color: white; cursor: pointer; }
        button.secondary { margin-top: .6rem; background: #526174; }
        .demo { display: grid; gap: .5rem; margin-top: 1.4rem; }
        .demo button { margin-top: 0; background: #e8eefc; color: #183d91; }
        #status { min-height: 1.4rem; margin-top: 1rem; white-space: pre-wrap; }
        small { color: #526174; }
    </style>
</head>
<body>
<main>
    <h1>IAM Platform</h1>
    <small>Use a local account to test the API session.</small>
    <form id="login-form">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Log in</button>
    </form>
    <div id="demo-buttons" class="demo" hidden>
        <small>Local demo accounts</small>
        <button type="button" data-user="demo-reader" data-password="DemoReaderPassword1">Use demo reader</button>
        <button type="button" data-user="demo-operator" data-password="DemoOperatorPassword1">Use demo operator</button>
        <button type="button" data-user="demo-developer" data-password="DemoDeveloperPassword1">Use demo developer</button>
    </div>
    <button id="session-button" class="secondary" type="button" hidden>Check current session</button>
    <button id="logout-button" class="secondary" type="button" hidden>Log out</button>
    <div id="status" role="status"></div>
</main>
<script>
const sessionKey = "iam-session-id";
const statusElement = document.getElementById("status");
const usernameElement = document.getElementById("username");
const passwordElement = document.getElementById("password");
const sessionButton = document.getElementById("session-button");
const logoutButton = document.getElementById("logout-button");

function headers() {
    const sessionId = sessionStorage.getItem(sessionKey);
    return sessionId ? {"X-Session-ID": sessionId} : {};
}

function showStatus(message) {
    statusElement.textContent = message;
}

function updateSessionControls() {
    const loggedIn = Boolean(sessionStorage.getItem(sessionKey));
    sessionButton.hidden = !loggedIn;
    logoutButton.hidden = !loggedIn;
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    showStatus("Signing in...");
    const response = await fetch("/auth/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username: usernameElement.value, password: passwordElement.value})
    });
    if (!response.ok) {
        showStatus((await response.json()).detail || "Login failed.");
        return;
    }
    const result = await response.json();
    sessionStorage.setItem(sessionKey, result.session_id);
    passwordElement.value = "";
    updateSessionControls();
    showStatus(`Logged in as ${result.user_id}. Session expires ${result.expires_at}.`);
});

sessionButton.addEventListener("click", async () => {
    const response = await fetch("/auth/session", {headers: headers()});
    showStatus(response.ok ? `Current user: ${(await response.json()).user_id}` : "Session is no longer valid.");
    if (!response.ok) { sessionStorage.removeItem(sessionKey); updateSessionControls(); }
});

logoutButton.addEventListener("click", async () => {
    const response = await fetch("/auth/logout", {method: "POST", headers: headers()});
    sessionStorage.removeItem(sessionKey);
    updateSessionControls();
    showStatus(response.ok ? "Logged out." : "The session was already invalid.");
});

for (const button of document.querySelectorAll("[data-user]")) {
    button.addEventListener("click", () => {
        usernameElement.value = button.dataset.user;
        passwordElement.value = button.dataset.password;
    });
}

document.getElementById("demo-buttons").hidden = !__DEMO_ENABLED__;
updateSessionControls();
</script>
</body>
</html>"""

WEB_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(service: IamService, startup_action: StartupAction | None = None) -> FastAPI:
    """Build an IAM API that can be mounted into a larger FastAPI application."""

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        if startup_action is not None:
            startup_action()
        yield

    application = FastAPI(title="IAM Platform", lifespan=lifespan)
    static_directory = Path(__file__).with_name("static")
    application.mount("/static", StaticFiles(directory=static_directory), name="static")

    @application.exception_handler(Exception)
    async def unexpected_error_handler(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    application.include_router(create_router(service))

    @application.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_page() -> HTMLResponse:
        demo_enabled = os.environ.get("IAM_SEED_DEMO_USERS", "false").lower() == "true"
        return HTMLResponse(LOGIN_PAGE.replace("__DEMO_ENABLED__", "true" if demo_enabled else "false"), headers=WEB_SECURITY_HEADERS)

    @application.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    def admin_page() -> HTMLResponse:
        return HTMLResponse(ADMIN_PAGE, headers=WEB_SECURITY_HEADERS)

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
