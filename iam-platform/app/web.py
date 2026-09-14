LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IAM Platform Login</title>
  <link rel="stylesheet" href="/static/login.css">
</head>
<body data-demo-enabled="__DEMO_ENABLED__">
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
<script src="/static/login.js" defer></script>
</body>
</html>"""

ADMIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IAM Admin Portal</title>
  <link rel="stylesheet" href="/static/admin.css">
</head>
<body>
<header>
  <div><h1>IAM Admin Portal</h1><small id="identity">Not authenticated</small></div>
  <div><button id="refresh" class="secondary" type="button">Refresh</button> <button id="logout" class="danger" type="button">Log out</button></div>
</header>
<main>
  <div id="status" role="status">Sign in to load administration data.</div>
  <div class="toolbar"><strong>Administration overview</strong><a href="/docs" target="_blank" rel="noreferrer">Open API docs</a></div>
  <section class="grid">
    <article class="panel"><h2>Users <button class="secondary" data-load="users">Refresh</button></h2><div id="users" class="table-wrap"></div></article>
    <article class="panel"><h2>Groups <button class="secondary" data-load="groups">Refresh</button></h2><div id="groups" class="table-wrap"></div></article>
    <article class="panel"><h2>Roles <button class="secondary" data-load="roles">Refresh</button></h2><div id="roles" class="table-wrap"></div></article>
    <article class="panel"><h2>Permissions <button class="secondary" data-load="permissions">Refresh</button></h2><div id="permissions" class="table-wrap"></div></article>
    <article class="panel"><h2>Applications <span><button id="new-application" type="button">Create</button> <button class="secondary" data-load="applications">Refresh</button></span></h2><div id="applications" class="table-wrap"></div></article>
    <article class="panel"><h2>Audit events <button class="secondary" data-load="audit">Refresh</button></h2><div id="audit" class="table-wrap"></div></article>
  </section>
</main>
<div id="application-modal" class="modal" hidden>
  <form id="application-form">
    <h2>Create application</h2>
    <label for="application-name">Name</label><input id="application-name" required maxlength="255">
    <label for="application-description">Description</label><textarea id="application-description" maxlength="2000"></textarea>
    <div class="form-actions"><button class="secondary" id="cancel-application" type="button">Cancel</button><button type="submit">Create</button></div>
  </form>
</div>
<script src="/static/admin.js" defer></script>
</body>
</html>"""
