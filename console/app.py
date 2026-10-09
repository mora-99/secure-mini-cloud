"""Mora Cloud Console - self-hosted, secure-by-design cloud portal.

Phase 3: OIDC login (Keycloak) with PKCE + MFA
Phase 4: Storage (Garage S3) with role-based access control
Phase 5: Tamper-evident audit log (hash chain)
Phase 6: Detection of suspicious activity (denied-access / failed-login alerts)
"""
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from urllib.parse import quote, urlencode

import boto3
from authlib.integrations.starlette_client import OAuth
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware

load_dotenv(Path(__file__).with_name(".env"))

# ---------------------------------------------------------------- config
KC_REALM = os.getenv("KC_REALM", "http://localhost:8081/realms/mora-cloud")
BASE = os.getenv("CONSOLE_BASE", "http://localhost:8000")
S3_ENDPOINT = os.getenv("S3_ENDPOINT", "http://127.0.0.1:3900") or None
S3_REGION = os.getenv("S3_REGION", "garage")
AUDIT_LOG = Path(os.getenv("AUDIT_LOG", str(Path(__file__).with_name("audit.log"))))
MAX_UPLOAD = 10 * 1024 * 1024          # 10 MB
ALERT_WINDOW = timedelta(minutes=15)
ALERT_THRESHOLD = 3

# Least privilege: each role gets only the permissions it needs.
PERMS = {
    "admin":     {"storage:list", "storage:read", "storage:write", "storage:delete", "audit:read"},
    "developer": {"storage:list", "storage:read", "storage:write"},
    "auditor":   {"storage:list", "storage:read", "audit:read"},
}
ROLES = set(PERMS)
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")

# ---------------------------------------------------------------- app
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"],
                   session_cookie="mora_session", same_site="lax", max_age=3600)

oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id="mora-console",
    client_secret=os.environ["KC_CLIENT_SECRET"],
    server_metadata_url=f"{KC_REALM}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)


@app.middleware("http")
async def security_headers(request, call_next):
    r = await call_next(request)
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self' " + KC_REALM.split("/realms")[0]
    return r


# ---------------------------------------------------------------- identity helpers
def current_user(request):
    return request.session.get("user")


def can(user, perm):
    return bool(user) and any(perm in PERMS.get(r, set()) for r in user.get("roles", []))


def csrf_field(request):
    return f"<input type='hidden' name='csrf' value='{escape(request.session.get('csrf', ''))}'>"


def csrf_ok(request, token):
    expected = request.session.get("csrf", "")
    return bool(expected) and secrets.compare_digest(expected, token or "")


# ---------------------------------------------------------------- audit log (Phase 5)
def _hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _read_entries():
    if not AUDIT_LOG.exists():
        return []
    out = []
    for line in AUDIT_LOG.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"_corrupt": line})
    return out


def audit(request, action, target="", result="OK", user=None):
    user = user or current_user(request) or {}
    entries = _read_entries()
    prev = entries[-1].get("hash", "CORRUPT") if entries else "GENESIS"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": user.get("username", "anonymous"),
        "roles": user.get("roles", []),
        "ip": request.client.host if request.client else "",
        "action": action,
        "target": target[:300],
        "result": result,
        "prev": prev,
    }
    entry["hash"] = _hash(entry)
    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def verify_chain(entries):
    """Return (True, None) if intact, else (False, line_number)."""
    prev = "GENESIS"
    for i, e in enumerate(entries, 1):
        if "_corrupt" in e or e.get("prev") != prev or e.get("hash") != _hash(e):
            return False, i
        prev = e["hash"]
    return True, None


def detect_alerts(entries, now=None):
    """Phase 6: flag users with repeated denied actions or failed logins."""
    now = now or datetime.now(timezone.utc)
    counts = {}
    for e in entries:
        if e.get("result") not in ("DENIED", "FAILED"):
            continue
        try:
            ts = datetime.fromisoformat(e["ts"])
        except (KeyError, ValueError):
            continue
        if now - ts <= ALERT_WINDOW:
            key = (e.get("user", "?"), e.get("result"))
            counts[key] = counts.get(key, 0) + 1
    return [(u, r, n) for (u, r), n in sorted(counts.items()) if n >= ALERT_THRESHOLD]


# ---------------------------------------------------------------- storage (Phase 4)
def s3_for(user):
    """Users who may write get the RW key; everyone else gets the read-only key.
    Defense in depth: even if the app had a bug, the RO key cannot write in Garage."""
    if can(user, "storage:write"):
        kid, sec = os.environ["S3_RW_KEY_ID"], os.environ["S3_RW_SECRET"]
    else:
        kid, sec = os.environ["S3_RO_KEY_ID"], os.environ["S3_RO_SECRET"]
    return boto3.client(
        "s3", endpoint_url=S3_ENDPOINT, region_name=S3_REGION,
        aws_access_key_id=kid, aws_secret_access_key=sec,
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2},
                      request_checksum_calculation="when_required",
                      response_checksum_validation="when_required"),
    )


def safe_filename(name):
    name = Path(name or "").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")[:200]
    return name or None


def valid_key(key):
    return bool(key) and len(key) <= 1024 and not any(ord(c) < 32 for c in key)


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- HTML
CSS = """body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
header{background:#1e293b;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.logo{font-weight:700;font-size:20px;color:#e2e8f0;text-decoration:none} .logo span{color:#38bdf8}
nav a{color:#cbd5e1;text-decoration:none;margin-right:18px} nav a:hover{color:#38bdf8}
main{max-width:960px;margin:40px auto;padding:0 24px}
a.btn,button{background:#38bdf8;color:#0f172a;padding:8px 16px;border-radius:6px;text-decoration:none;font-weight:600;border:0;cursor:pointer;font-size:14px}
button.danger{background:#f87171}
.card{background:#1e293b;border-radius:10px;padding:20px 24px;margin-top:20px}
.tag{display:inline-block;background:#0ea5e9;color:#0f172a;border-radius:4px;padding:2px 8px;margin-right:6px;font-size:13px;font-weight:600}
.ok{color:#4ade80} .bad{color:#f87171} .muted{color:#94a3b8}
.alert{background:#7f1d1d;border:1px solid #f87171;border-radius:8px;padding:12px 16px;margin-top:16px}
table{width:100%;border-collapse:collapse;font-size:14px} th,td{text-align:left;padding:8px;border-bottom:1px solid #334155;vertical-align:top}
th{color:#94a3b8;font-weight:600} td form{display:inline} a{color:#38bdf8}
input[type=file]{color:#e2e8f0}"""


def page(request, body, status=200):
    user = current_user(request)
    nav = ""
    right = ""
    if user:
        links = ["<a href='/'>Dashboard</a>"]
        if can(user, "storage:list"):
            links.append("<a href='/storage'>Storage</a>")
        if can(user, "audit:read"):
            links.append("<a href='/audit'>Audit log</a>")
        nav = "<nav>" + "".join(links) + "</nav>"
        right = f"<div>{escape(user['username'])} &nbsp; <a class='btn' href='/logout'>Sign out</a></div>"
    html = (f"<!doctype html><html><head><meta charset='utf-8'><title>Mora Cloud</title>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body>"
            f"<header><a class='logo' href='/'>Mora <span>Cloud</span></a>{nav}{right}</header>"
            f"<main>{body}</main></body></html>")
    return HTMLResponse(html, status_code=status)


def denied(request, perm, target=""):
    audit(request, perm, target, "DENIED")
    return page(request, "<h1 class='bad'>403 — Access denied</h1>"
                         f"<p>Your role does not include <code>{escape(perm)}</code>. "
                         "This attempt has been recorded in the audit log.</p>"
                         "<p><a href='/'>Back to dashboard</a></p>", status=403)


def require(request, perm, target=""):
    """Returns (user, None) if allowed, else (user, response)."""
    user = current_user(request)
    if not user:
        return None, RedirectResponse("/", status_code=303)
    if not can(user, perm):
        return user, denied(request, perm, target)
    return user, None


def storage_error(request, err, action, target):
    code = err.response.get("Error", {}).get("Code", "Error") if isinstance(err, ClientError) else "StorageUnavailable"
    result = "DENIED" if code in ("AccessDenied", "Forbidden", "403") else "ERROR"
    audit(request, action, target, result)
    return page(request, f"<h1 class='bad'>Storage error</h1><p>{escape(code)}</p>"
                         "<p><a href='/storage'>Back to storage</a></p>",
                status=403 if result == "DENIED" else 502)


# ---------------------------------------------------------------- routes: auth (Phase 3)
@app.get("/")
async def home(request: Request):
    user = current_user(request)
    if not user:
        return page(request, "<h1>Mora Cloud Console</h1><p>Secure self-hosted cloud. "
                             "Sign in with your Mora Cloud identity (MFA required).</p>"
                             "<p><a class='btn' href='/login'>Sign in</a></p>")
    roles = "".join(f"<span class='tag'>{escape(r)}</span>" for r in user["roles"]) or "<em>no role</em>"
    perms = sorted(set().union(*(PERMS.get(r, set()) for r in user["roles"]))) if user["roles"] else []
    perm_html = ", ".join(f"<code>{escape(p)}</code>" for p in perms) or "<em>none</em>"
    return page(request,
                f"<h1>Welcome {escape(user['name'])}</h1><div class='card'>"
                f"<p><b>User:</b> {escape(user['username'])}</p>"
                f"<p><b>Email:</b> {escape(user['email'])}</p>"
                f"<p><b>Roles:</b> {roles}</p>"
                f"<p><b>Permissions:</b> {perm_html}</p></div>")


@app.get("/login")
async def login(request: Request):
    return await oauth.keycloak.authorize_redirect(request, f"{BASE}/callback")


@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
        info = token["userinfo"]
    except Exception as exc:  # bad state, expired code, wrong secret...
        audit(request, "login", type(exc).__name__, "FAILED")
        return page(request, "<h1 class='bad'>Sign-in failed</h1><p>Please try again.</p>"
                             "<p><a class='btn' href='/login'>Sign in</a></p>", status=400)
    request.session.clear()  # new session on login
    user = {
        "username": info.get("preferred_username", ""),
        "name": info.get("given_name") or info.get("preferred_username", ""),
        "email": info.get("email", ""),
        "roles": sorted(ROLES.intersection(info.get("roles", []))),
    }
    request.session["user"] = user
    request.session["csrf"] = secrets.token_urlsafe(32)
    audit(request, "login", "console", "OK", user=user)
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    if current_user(request):
        audit(request, "logout", "console", "OK")
    request.session.clear()
    meta = await oauth.keycloak.load_server_metadata()
    q = urlencode({"client_id": "mora-console", "post_logout_redirect_uri": BASE + "/"})
    return RedirectResponse(f"{meta['end_session_endpoint']}?{q}", status_code=303)


# ---------------------------------------------------------------- routes: storage (Phase 4)
@app.get("/storage")
async def storage(request: Request):
    user, resp = require(request, "storage:list", "*")
    if resp:
        return resp
    try:
        buckets = s3_for(user).list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as e:
        return storage_error(request, e, "storage:list", "*")
    rows = "".join(
        f"<tr><td><a href='/storage/{quote(b['Name'])}'>{escape(b['Name'])}</a></td>"
        f"<td class='muted'>{escape(str(b.get('CreationDate', ''))[:19])}</td></tr>" for b in buckets
    ) or "<tr><td colspan='2' class='muted'>No buckets visible to your key.</td></tr>"
    return page(request, "<h1>Storage</h1><p class='muted'>Buckets in Garage (S3-compatible), "
                         "filtered by what your role's key can access.</p>"
                         f"<div class='card'><table><tr><th>Bucket</th><th>Created</th></tr>{rows}</table></div>")


@app.get("/storage/{bucket}")
async def bucket_view(request: Request, bucket: str):
    user, resp = require(request, "storage:read", bucket)
    if resp:
        return resp
    if not BUCKET_RE.match(bucket):
        return page(request, "<h1 class='bad'>Invalid bucket name</h1>", status=400)
    try:
        objs = s3_for(user).list_objects_v2(Bucket=bucket, MaxKeys=500).get("Contents", [])
    except (ClientError, BotoCoreError) as e:
        return storage_error(request, e, "storage:read", bucket)
    rows = ""
    for o in objs:
        k = o["Key"]
        dl = f"<a href='/storage/{quote(bucket)}/download?key={quote(k, safe='')}'>Download</a>"
        rm = ""
        if can(user, "storage:delete"):
            rm = (f" &nbsp; <form method='post' action='/storage/{quote(bucket)}/delete'>{csrf_field(request)}"
                  f"<input type='hidden' name='key' value='{escape(k)}'>"
                  f"<button class='danger' type='submit'>Delete</button></form>")
        rows += (f"<tr><td>{escape(k)}</td><td>{human(o.get('Size', 0))}</td>"
                 f"<td class='muted'>{escape(str(o.get('LastModified', ''))[:19])}</td><td>{dl}{rm}</td></tr>")
    rows = rows or "<tr><td colspan='4' class='muted'>Empty bucket.</td></tr>"
    upload = ""
    if can(user, "storage:write"):
        upload = (f"<div class='card'><h3>Upload file (max 10 MB)</h3>"
                  f"<form method='post' action='/storage/{quote(bucket)}/upload' enctype='multipart/form-data'>"
                  f"{csrf_field(request)}<input type='file' name='file' required> <button type='submit'>Upload</button></form></div>")
    else:
        upload = "<p class='muted'>Read-only access: your role cannot upload or delete.</p>"
    audit(request, "storage:read", bucket, "OK")
    return page(request, f"<p><a href='/storage'>&larr; All buckets</a></p><h1>{escape(bucket)}</h1>{upload}"
                         f"<div class='card'><table><tr><th>Object</th><th>Size</th><th>Modified</th><th></th></tr>{rows}</table></div>")


@app.get("/storage/{bucket}/download")
async def download(request: Request, bucket: str, key: str):
    user, resp = require(request, "storage:read", f"{bucket}/{key}")
    if resp:
        return resp
    if not BUCKET_RE.match(bucket) or not valid_key(key):
        return page(request, "<h1 class='bad'>Invalid request</h1>", status=400)
    try:
        obj = s3_for(user).get_object(Bucket=bucket, Key=key)
    except (ClientError, BotoCoreError) as e:
        return storage_error(request, e, "storage:download", f"{bucket}/{key}")
    audit(request, "storage:download", f"{bucket}/{key}", "OK")
    fname = safe_filename(key) or "download"
    # Always force download as octet-stream: an uploaded .html file can never run in the console (stored XSS).
    return StreamingResponse(obj["Body"].iter_chunks(), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/storage/{bucket}/upload")
async def upload(request: Request, bucket: str, file: UploadFile = File(...), csrf: str = Form("")):
    user, resp = require(request, "storage:write", bucket)
    if resp:
        return resp
    if not csrf_ok(request, csrf):
        audit(request, "storage:write", bucket, "DENIED-CSRF")
        return page(request, "<h1 class='bad'>Invalid form token</h1>", status=403)
    name = safe_filename(file.filename)
    if not BUCKET_RE.match(bucket) or not name:
        return page(request, "<h1 class='bad'>Invalid bucket or file name</h1>", status=400)
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        audit(request, "storage:write", f"{bucket}/{name}", "REJECTED-SIZE")
        return page(request, "<h1 class='bad'>File too large (max 10 MB)</h1>", status=413)
    try:
        s3_for(user).put_object(Bucket=bucket, Key=name, Body=data)
    except (ClientError, BotoCoreError) as e:
        return storage_error(request, e, "storage:write", f"{bucket}/{name}")
    audit(request, "storage:write", f"{bucket}/{name}", "OK")
    return RedirectResponse(f"/storage/{quote(bucket)}", status_code=303)


@app.post("/storage/{bucket}/delete")
async def delete(request: Request, bucket: str, key: str = Form(""), csrf: str = Form("")):
    user, resp = require(request, "storage:delete", f"{bucket}/{key}")
    if resp:
        return resp
    if not csrf_ok(request, csrf):
        audit(request, "storage:delete", f"{bucket}/{key}", "DENIED-CSRF")
        return page(request, "<h1 class='bad'>Invalid form token</h1>", status=403)
    if not BUCKET_RE.match(bucket) or not valid_key(key):
        return page(request, "<h1 class='bad'>Invalid request</h1>", status=400)
    try:
        s3_for(user).delete_object(Bucket=bucket, Key=key)
    except (ClientError, BotoCoreError) as e:
        return storage_error(request, e, "storage:delete", f"{bucket}/{key}")
    audit(request, "storage:delete", f"{bucket}/{key}", "OK")
    return RedirectResponse(f"/storage/{quote(bucket)}", status_code=303)


# ---------------------------------------------------------------- routes: audit + detection (Phases 5-6)
@app.get("/audit")
async def audit_view(request: Request):
    user, resp = require(request, "audit:read", "audit.log")
    if resp:
        return resp
    entries = _read_entries()
    intact, bad_line = verify_chain(entries)
    status = ("<p class='ok'>&#10004; Hash chain intact — no entries were modified or deleted.</p>" if intact else
              f"<p class='bad'>&#10008; TAMPERING DETECTED at line {bad_line} — the log was edited.</p>")
    alerts = "".join(
        f"<div class='alert'>&#9888; <b>{escape(u)}</b>: {n} {'denied actions' if r == 'DENIED' else 'failed sign-ins'} "
        f"in the last {int(ALERT_WINDOW.total_seconds() // 60)} minutes — possible "
        f"{'privilege probing' if r == 'DENIED' else 'brute-force / token attack'}.</div>"
        for u, r, n in detect_alerts(entries))
    rows = ""
    for e in reversed(entries[-200:]):
        if "_corrupt" in e:
            rows += "<tr><td colspan='5' class='bad'>corrupt line</td></tr>"
            continue
        res = e.get("result", "")
        cls = "ok" if res == "OK" else "bad"
        rows += (f"<tr><td class='muted'>{escape(e.get('ts', ''))}</td><td>{escape(e.get('user', ''))}</td>"
                 f"<td>{escape(e.get('action', ''))}</td><td>{escape(e.get('target', ''))}</td>"
                 f"<td class='{cls}'>{escape(res)}</td></tr>")
    audit(request, "audit:read", "audit.log", "OK")
    return page(request, "<h1>Audit log</h1><p class='muted'>Every sign-in, storage action and denied attempt. "
                         "Each entry includes the SHA-256 hash of the previous one (tamper-evident chain).</p>"
                         f"{status}{alerts}<div class='card'><table><tr><th>Time (UTC)</th><th>User</th><th>Action</th>"
                         f"<th>Target</th><th>Result</th></tr>{rows or '<tr><td colspan=5>No events yet.</td></tr>'}</table></div>")
