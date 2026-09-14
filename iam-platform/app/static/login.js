const sessionKey = "iam-session-id";
const statusElement = document.getElementById("status");
const usernameElement = document.getElementById("username");
const passwordElement = document.getElementById("password");
const sessionButton = document.getElementById("session-button");
const logoutButton = document.getElementById("logout-button");

function headers() { const sessionId = sessionStorage.getItem(sessionKey); return sessionId ? {"X-Session-ID": sessionId} : {}; }
function showStatus(message) { statusElement.textContent = message; }
function updateSessionControls() { const loggedIn = Boolean(sessionStorage.getItem(sessionKey)); sessionButton.hidden = !loggedIn; logoutButton.hidden = !loggedIn; }

document.getElementById("login-form").addEventListener("submit", async event => {
  event.preventDefault(); showStatus("Signing in...");
  const response = await fetch("/auth/login", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username: usernameElement.value, password: passwordElement.value})});
  if (!response.ok) { showStatus((await response.json()).detail || "Login failed."); return; }
  const result = await response.json(); sessionStorage.setItem(sessionKey, result.session_id); passwordElement.value = ""; updateSessionControls();
  showStatus(`Logged in as ${result.user_id}. Session expires ${result.expires_at}.`);
});

sessionButton.addEventListener("click", async () => {
  const response = await fetch("/auth/session", {headers: headers()});
  showStatus(response.ok ? `Current user: ${(await response.json()).user_id}` : "Session is no longer valid.");
  if (!response.ok) { sessionStorage.removeItem(sessionKey); updateSessionControls(); }
});
logoutButton.addEventListener("click", async () => { const response = await fetch("/auth/logout", {method: "POST", headers: headers()}); sessionStorage.removeItem(sessionKey); updateSessionControls(); showStatus(response.ok ? "Logged out." : "The session was already invalid."); });
for (const button of document.querySelectorAll("[data-user]")) button.addEventListener("click", () => { usernameElement.value = button.dataset.user; passwordElement.value = button.dataset.password; });
document.getElementById("demo-buttons").hidden = document.body.dataset.demoEnabled !== "true";
updateSessionControls();
