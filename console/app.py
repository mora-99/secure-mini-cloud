import os
from html import escape
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

load_dotenv()

KC_REALM = "http://localhost:8081/realms/mora-cloud"
BASE = "http://localhost:8000"
ROLES = {"admin", "developer", "auditor"}

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
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
    return r


def page(nav, body):
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><title>Mora Cloud</title>
<style>body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}}
header{{background:#1e293b;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}}
.logo{{font-weight:700;font-size:20px}} .logo span{{color:#38bdf8}}
main{{max-width:760px;margin:60px auto;padding:0 24px}}
a.btn{{background:#38bdf8;color:#0f172a;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600}}
.card{{background:#1e293b;border-radius:10px;padding:24px;margin-top:20px}}
.tag{{display:inline-block;background:#0ea5e9;color:#0f172a;border-radius:4px;padding:2px 8px;margin-right:6px;font-size:13px;font-weight:600}}
</style></head><body><header><div class="logo">Mora <span>Cloud</span></div><div>{nav}</div></header>
<main>{body}</main></body></html>""")


@app.get("/")
async def home(request: Request):
    user = request.session.get("user")
    if not user:
        return page("", "<h1>Mora Cloud Console</h1><p>Secure self-hosted cloud. "
                        "Sign in with your Mora Cloud identity (MFA required).</p>"
                        "<p><a class='btn' href='/login'>Sign in</a></p>")
    roles = "".join(f"<span class='tag'>{escape(r)}</span>" for r in user["roles"]) or "<em>no role</em>"
    return page(f"{escape(user['username'])} &nbsp; <a class='btn' href='/logout'>Sign out</a>",
                f"<h1>Welcome {escape(user['name'])}</h1><div class='card'>"
                f"<p><b>User:</b> {escape(user['username'])}</p>"
                f"<p><b>Email:</b> {escape(user['email'])}</p>"
                f"<p><b>Roles:</b> {roles}</p></div>")


@app.get("/login")
async def login(request: Request):
    return await oauth.keycloak.authorize_redirect(request, f"{BASE}/callback")


@app.get("/callback")
async def callback(request: Request):
    token = await oauth.keycloak.authorize_access_token(request)
    info = token["userinfo"]
    request.session.clear()
    request.session["user"] = {
        "username": info.get("preferred_username", ""),
        "name": info.get("given_name") or info.get("preferred_username", ""),
        "email": info.get("email", ""),
        "roles": sorted(ROLES.intersection(info.get("roles", []))),
    }
    return RedirectResponse("/")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    meta = await oauth.keycloak.load_server_metadata()
    q = urlencode({"client_id": "mora-console", "post_logout_redirect_uri": BASE + "/"})
    return RedirectResponse(f"{meta['end_session_endpoint']}?{q}")
