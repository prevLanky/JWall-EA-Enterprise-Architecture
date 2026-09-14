const sessionKey = "iam-session-id";
const statusElement = document.getElementById("status");
const sessionId = sessionStorage.getItem(sessionKey);
const endpoints = {users: "/users", groups: "/groups", roles: "/roles", permissions: "/permissions", applications: "/applications", audit: "/audit"};
const columns = {
  users: ["username", "email", "display_name", "is_active"], groups: ["name", "description"], roles: ["name", "description"],
  permissions: ["resource", "action"], applications: ["name", "description"], audit: ["event_type", "result", "target_type", "timestamp"]
};

function setStatus(message, error = false) { statusElement.textContent = message; statusElement.className = error ? "error" : ""; }
function headers() { return {"X-Session-ID": sessionId, "Content-Type": "application/json"}; }
function render(name, records) {
  const target = document.getElementById(name);
  target.replaceChildren();
  if (!records.length) {
    const empty = document.createElement("div"); empty.className = "empty"; empty.textContent = "No records."; target.append(empty); return;
  }
  const table = document.createElement("table"); const head = document.createElement("thead"); const headRow = document.createElement("tr");
  for (const column of columns[name]) { const cell = document.createElement("th"); cell.textContent = column; headRow.append(cell); }
  head.append(headRow); const body = document.createElement("tbody");
  for (const record of records) {
    const row = document.createElement("tr");
    for (const column of columns[name]) { const cell = document.createElement("td"); cell.textContent = String(record[column] ?? ""); row.append(cell); }
    body.append(row);
  }
  table.append(head, body); target.append(table);
}
async function load(name) {
  const response = await fetch(endpoints[name], {headers: headers()});
  if (response.status === 401) { sessionStorage.removeItem(sessionKey); window.location.href = "/login"; return; }
  if (response.status === 403) { setStatus(`Cannot load ${name}: HTTP 403.`, true); return; }
  if (!response.ok) { setStatus(`Cannot load ${name}: HTTP ${response.status}.`, true); return; }
  render(name, await response.json()); setStatus(`Loaded ${name}.`);
}
async function loadAll() { if (!sessionId) { setStatus("No session found. Sign in at /login first.", true); return; } for (const name of Object.keys(endpoints)) await load(name); }

document.getElementById("refresh").addEventListener("click", loadAll);
document.getElementById("logout").addEventListener("click", async () => { await fetch("/auth/logout", {method: "POST", headers: headers()}); sessionStorage.removeItem(sessionKey); window.location.href = "/login"; });
for (const button of document.querySelectorAll("[data-load]")) button.addEventListener("click", () => load(button.dataset.load));
document.getElementById("new-application").addEventListener("click", () => { document.getElementById("application-modal").hidden = false; });
document.getElementById("cancel-application").addEventListener("click", () => { document.getElementById("application-modal").hidden = true; });
document.getElementById("application-form").addEventListener("submit", async event => {
  event.preventDefault();
  const response = await fetch("/applications", {method: "POST", headers: headers(), body: JSON.stringify({name: document.getElementById("application-name").value, description: document.getElementById("application-description").value})});
  if (response.status === 401) { sessionStorage.removeItem(sessionKey); window.location.href = "/login"; return; }
  if (!response.ok) { setStatus(`Application creation failed: HTTP ${response.status}.`, true); return; }
  document.getElementById("application-modal").hidden = true; event.target.reset(); await load("applications");
});
document.getElementById("identity").textContent = sessionId ? "Session available" : "Not authenticated";
loadAll();
