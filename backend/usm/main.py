"""Universal Secret Manager API. Secret values are write-only: never returned, logged or echoed."""
from __future__ import annotations

import hmac
import secrets

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from usm import config
from usm.db import DB, RANK, ROLES
from usm.providers import ProviderError, make_provider

S = config.load()
db = DB(S.database_url)
db.bootstrap_admins(S.initial_admins)
VAULTS: dict = {}
VAULT_ERRORS: dict = {}            # a vault with bad credentials must not stop sign-in or the other vaults
for _v in S.vaults:
    try:
        VAULTS[_v["id"]] = (_v.get("label", _v["id"]), make_provider(_v))
    except Exception as e:  # noqa: BLE001 - shown to admins, never contains values
        VAULT_ERRORS[_v["id"]] = (_v.get("label", _v["id"]), f"vault not available: {e if isinstance(e, ProviderError) else type(e).__name__ + ': ' + str(e)}"[:300])

app = FastAPI(title="Universal Secret Manager", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=S.session_key, session_cookie="usm_session",
                   max_age=S.session_hours * 3600, same_site="lax", https_only=S.base_url.startswith("https://"))

oauth = OAuth()
if not S.dev_login:
    oauth.register("google", client_id=S.google_client_id, client_secret=S.google_client_secret,
                   server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
                   client_kwargs={"scope": "openid email profile"})


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    return resp


def ip(request: Request) -> str:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


# ---- auth ----------------------------------------------------------------------------------------------------
class User:
    def __init__(self, email: str, role: str):
        self.email, self.role = email, role

    def can(self, role: str) -> bool:
        return RANK[self.role] >= RANK[role]


def session_user(request: Request) -> User:
    email = request.session.get("user")
    u = db.get_user(email) if email else None
    if not u or not u["active"]:            # role / deactivation take effect on the next request
        request.session.clear()
        raise HTTPException(401, "not signed in")
    return User(u["email"], u["role"])


def needs(role: str):
    def dep(request: Request, user: User = Depends(session_user)) -> User:
        if not user.can(role):
            raise HTTPException(403, f"needs role '{role}'")
        if request.method not in ("GET", "HEAD"):
            token = request.headers.get("x-csrf-token", "")
            if not hmac.compare_digest(request.session.get("csrf", ""), token):
                raise HTTPException(400, "invalid CSRF token - reload the page")
        return user
    return dep


def login_ok(email: str) -> bool:
    return any(email.endswith("@" + d) for d in S.allowed_domains)


def start_session(request: Request, email: str) -> None:
    request.session.clear()
    request.session.update(user=email, csrf=secrets.token_urlsafe(32))
    db.touch_login(email)
    db.audit(email, "login", True, client_ip=ip(request))


@app.get("/auth/login")
async def auth_login(request: Request):
    if S.dev_login:
        raise HTTPException(400, "dev login mode - use the dev form")
    hd = S.allowed_domains[0] if len(S.allowed_domains) == 1 else None
    return await oauth.google.authorize_redirect(request, f"{S.base_url}/auth/callback", prompt="select_account",
                                                 **({"hd": hd} if hd else {}))


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        info = (await oauth.google.authorize_access_token(request)).get("userinfo") or {}
    except OAuthError as e:
        db.audit("-", "login", False, client_ip=ip(request), reason=e.error)
        return RedirectResponse("/#/login?e=oauth", 303)
    email = (info.get("email") or "").lower()
    hd = (info.get("hd") or "").lower()
    u = db.get_user(email)
    if not (info.get("email_verified") and login_ok(email) and hd in S.allowed_domains and u and u["active"]):
        db.audit(email or "-", "login", False, client_ip=ip(request), reason="not allowed")
        return RedirectResponse("/#/login?e=denied", 303)
    start_session(request, email)
    return RedirectResponse("/", 303)


@app.post("/auth/dev")
async def auth_dev(request: Request, email: str = Form(...)):
    email = email.lower()
    u = db.get_user(email)
    if not (S.dev_login and login_ok(email) and u and u["active"]):
        raise HTTPException(403, "dev login not allowed")
    start_session(request, email)
    return {"ok": True}


@app.post("/auth/logout")
async def auth_logout(request: Request):
    email = request.session.get("user")
    request.session.clear()
    if email:
        db.audit(email, "logout", True, client_ip=ip(request))
    return {"ok": True}


@app.get("/api/me")
async def me(request: Request):
    base = {"instance": S.instance_name, "banner": S.banner, "dev_login": S.dev_login}
    try:
        u = session_user(request)
    except HTTPException:
        return {**base, "user": None}
    can_reveal = S.reveal_role != "none" and u.can(S.reveal_role)
    return {**base, "user": u.email, "role": u.role, "csrf": request.session["csrf"],
            "can_reveal": can_reveal, "reveal_seconds": S.reveal_seconds}


@app.get("/api/health")
async def health():
    return {"ok": db.ping()}


# ---- vaults --------------------------------------------------------------------------------------------------
def vault(vid: str):
    if vid in VAULT_ERRORS:
        raise HTTPException(503, VAULT_ERRORS[vid][1])
    if vid not in VAULTS:
        raise HTTPException(404, "unknown vault")
    return VAULTS[vid][1]


def provider_call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ProviderError as e:
        raise HTTPException(409, str(e))


@app.get("/api/vaults")
async def list_vaults(user: User = Depends(needs("viewer"))):
    ok = [{"id": vid, "label": label, "location": p.location(), "kind": p.kind, "can_destroy_versions": p.can_destroy_versions}
          for vid, (label, p) in VAULTS.items()]
    return ok + [{"id": vid, "label": label, "location": err, "kind": "error"} for vid, (label, err) in VAULT_ERRORS.items()]


@app.get("/api/vaults/{vid}/bundles")
async def list_bundles(vid: str, user: User = Depends(needs("viewer"))):
    return [{"name": b.name, "updated": b.updated} for b in provider_call(vault(vid).list_bundles)]


@app.get("/api/vaults/{vid}/bundles/{bundle}")
async def get_bundle(vid: str, bundle: str, user: User = Depends(needs("viewer"))):
    keys, ver = provider_call(vault(vid).list_keys, bundle)
    return {"bundle": bundle, "version": ver, "keys": keys}


@app.put("/api/vaults/{vid}/bundles/{bundle}/keys/{key}")
async def set_key(request: Request, vid: str, bundle: str, key: str, mode: str = Form(...), value: str = Form(""),
                  file: UploadFile | None = File(None), expect_version: str = Form(""),
                  user: User = Depends(needs("editor"))):
    if mode not in ("create", "update"):
        raise HTTPException(400, "mode must be create or update")
    raw = await file.read() if file and file.filename else value.replace("\r\n", "\n").encode()
    if len(raw) > S.max_value_bytes:
        raise HTTPException(413, f"value too large (max {S.max_value_bytes // 1024} KB)")
    try:
        val = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "value must be UTF-8 text (base64-encode binary files first)")
    action = "update_key" if mode == "update" else "add_key"
    try:
        new = vault(vid).set_key(bundle, key, val, must_exist=mode == "update", expect_version=expect_version or None)
    except ProviderError as e:
        db.audit(user.email, action, False, vid, bundle, key, expect_version, client_ip=ip(request), reason=str(e))
        raise HTTPException(409, str(e))
    db.audit(user.email, action, True, vid, bundle, key, expect_version, new, client_ip=ip(request),
             source="file" if file and file.filename else "form")
    return {"version": new}


class Confirm(BaseModel):
    confirm: str
    expect_version: str = ""


class Reveal(BaseModel):
    reason: str


@app.post("/api/vaults/{vid}/bundles/{bundle}/keys/{key}/reveal")
async def reveal_key(request: Request, vid: str, bundle: str, key: str, body: Reveal,
                     user: User = Depends(session_user)):
    """Return ONE value. Only for reveal.role; needs a reason; always audited (never the value itself)."""
    if S.reveal_role == "none" or not user.can(S.reveal_role):
        raise HTTPException(403, "viewing secret values is not allowed for your role")
    if not hmac.compare_digest(request.session.get("csrf", ""), request.headers.get("x-csrf-token", "")):
        raise HTTPException(400, "invalid CSRF token - reload the page")
    reason = body.reason.strip()
    if len(reason) < 5:
        raise HTTPException(400, "give a short reason (min 5 characters) - it goes into the audit log")
    try:
        value, ver = vault(vid).reveal(bundle, key)
    except ProviderError as e:
        db.audit(user.email, "reveal_key", False, vid, bundle, key, client_ip=ip(request), reason=str(e))
        raise HTTPException(409, str(e))
    db.audit(user.email, "reveal_key", True, vid, bundle, key, ver, client_ip=ip(request), why=reason[:200])
    return JSONResponse({"value": value, "version": ver, "seconds": S.reveal_seconds},
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.post("/api/vaults/{vid}/bundles/{bundle}/keys/{key}/delete")
async def delete_key(request: Request, vid: str, bundle: str, key: str, body: Confirm,
                     user: User = Depends(needs("admin"))):        # deletes are admin-only
    if body.confirm != key:
        raise HTTPException(400, "type the exact key name to confirm")
    try:
        new = vault(vid).delete_key(bundle, key, expect_version=body.expect_version or None)
    except ProviderError as e:
        db.audit(user.email, "delete_key", False, vid, bundle, key, body.expect_version, client_ip=ip(request), reason=str(e))
        raise HTTPException(409, str(e))
    db.audit(user.email, "delete_key", True, vid, bundle, key, body.expect_version, new, client_ip=ip(request))
    return {"version": new}


@app.get("/api/vaults/{vid}/bundles/{bundle}/versions")
async def versions(vid: str, bundle: str, user: User = Depends(needs("viewer"))):
    return [{"id": v.id, "created": v.created, "state": v.state} for v in provider_call(vault(vid).versions, bundle)]


@app.get("/api/vaults/{vid}/bundles/{bundle}/versions/{version}/diff")
async def version_diff(vid: str, bundle: str, version: str, user: User = Depends(needs("viewer"))):
    added, removed, changed = provider_call(vault(vid).key_diff, bundle, version)
    return {"added": added, "removed": removed, "changed": changed}


@app.post("/api/vaults/{vid}/bundles/{bundle}/versions/{version}/restore")
async def restore(request: Request, vid: str, bundle: str, version: str, body: Confirm,
                  user: User = Depends(needs("editor"))):
    if body.confirm != version:
        raise HTTPException(400, "type the version number to confirm")
    try:
        new = vault(vid).restore_version(bundle, version)
    except ProviderError as e:
        db.audit(user.email, "restore_version", False, vid, bundle, client_ip=ip(request), restored=version, reason=str(e))
        raise HTTPException(409, str(e))
    db.audit(user.email, "restore_version", True, vid, bundle, None, version, new, client_ip=ip(request))
    return {"version": new}


@app.post("/api/vaults/{vid}/bundles/{bundle}/versions/{version}/destroy")
async def destroy_version(request: Request, vid: str, bundle: str, version: str, body: Confirm,
                          user: User = Depends(needs("admin"))):
    """Permanently delete an OLD version. The current version and the bundle itself cannot be deleted."""
    if body.confirm != version:
        raise HTTPException(400, "type the version number to confirm")
    try:
        vault(vid).destroy_version(bundle, version)
    except ProviderError as e:
        db.audit(user.email, "delete_version", False, vid, bundle, None, version, client_ip=ip(request), reason=str(e))
        raise HTTPException(409, str(e))
    db.audit(user.email, "delete_version", True, vid, bundle, None, version, client_ip=ip(request))
    return {"ok": True}


# ---- admin ---------------------------------------------------------------------------------------------------
@app.get("/api/audit")
async def audit(limit: int = 200, bundle: str | None = None, actor: str | None = None,
                user: User = Depends(needs("admin"))):
    return db.list_audit(limit, bundle, actor)


@app.get("/api/users")
async def users(user: User = Depends(needs("admin"))):
    return db.list_users()


class UserIn(BaseModel):
    email: str
    role: str
    active: bool = True


@app.put("/api/users")
async def put_user(request: Request, body: UserIn, user: User = Depends(needs("admin"))):
    email = body.email.strip().lower()
    if not login_ok(email):
        raise HTTPException(400, f"email must be in: {', '.join(S.allowed_domains)}")
    if body.role not in ROLES:
        raise HTTPException(400, f"role must be one of {', '.join(ROLES)}")
    cur = db.get_user(email)
    if cur and cur["role"] == "admin" and cur["active"] and (body.role != "admin" or not body.active) \
            and db.count_active_admins() <= 1:
        raise HTTPException(400, "cannot remove the last active admin")
    db.upsert_user(email, body.role, body.active, user.email)
    db.audit(user.email, "set_user", True, client_ip=ip(request), target=email, role=body.role, active=body.active)
    return {"ok": True}


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, exc.status_code)
