"""End-to-end API tests against a running stack with config/test.yaml (memory vault + dev login).
Run: USM_E2E_URL=http://frontend:8080 pytest tests/test_e2e_api.py"""
import os
import secrets

import httpx
import pytest

URL = os.environ.get("USM_E2E_URL")
pytestmark = pytest.mark.skipif(not URL, reason="USM_E2E_URL not set")
V = "/api/vaults/test"
SEEDED = ["seed-value-alpha-123", "seed-value-beta-456"]     # values seeded in config/test.yaml


def client(email=None):
    c = httpx.Client(base_url=URL, follow_redirects=False, timeout=15)
    if email:
        r = c.post("/auth/dev", data={"email": email})
        assert r.status_code == 200, r.text
        c.headers["x-csrf-token"] = c.get("/api/me").json()["csrf"]
    return c


def assert_no_values(text, values):
    for v in values:
        assert v not in text, "a secret value leaked into a response"


@pytest.fixture(scope="module")
def admin():
    return client("admin@example.com")


@pytest.fixture(scope="module")
def users(admin):
    for email, role in (("editor@example.com", "editor"), ("viewer@example.com", "viewer")):
        assert admin.put("/api/users", json={"email": email, "role": role, "active": True}).status_code == 200
    return client("editor@example.com"), client("viewer@example.com")


def test_health_and_anonymous():
    c = client()
    assert c.get("/api/health").json() == {"ok": True}
    me = c.get("/api/me").json()
    assert me["user"] is None and me["dev_login"] is True
    assert c.get(f"{V}/bundles").status_code == 401


def test_login_refused_for_unknown_or_foreign():
    c = client()
    assert c.post("/auth/dev", data={"email": "stranger@example.com"}).status_code == 403
    assert c.post("/auth/dev", data={"email": "admin@other.com"}).status_code == 403


def test_security_headers():
    c = client()
    r = c.get("/")
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"):
        assert h in r.headers, h
    assert "no-store" in c.get("/api/me").headers.get("cache-control", "")


def test_browse_never_returns_values(admin):
    vaults = admin.get("/api/vaults").json()
    assert [v["id"] for v in vaults] == ["test"]
    bundles = admin.get(f"{V}/bundles").json()
    assert {b["name"] for b in bundles} >= {"stg--api", "stg--web"}
    r = admin.get(f"{V}/bundles/stg--api")
    assert r.json()["keys"] == ["api-secret__DB_PASSWORD", "api-secret__TOKEN"]
    assert_no_values(r.text, SEEDED)
    assert admin.get(f"{V}/bundles/not-managed").status_code == 409
    assert admin.get("/api/vaults/nope/bundles").status_code == 404


def test_csrf_required(admin):
    c = client("admin@example.com")
    del c.headers["x-csrf-token"]
    r = c.put(f"{V}/bundles/stg--api/keys/api-secret__TOKEN", data={"mode": "update", "value": "x"})
    assert r.status_code == 400 and "CSRF" in r.json()["error"]


def test_viewer_is_read_only(users):
    _, viewer = users
    assert viewer.get(f"{V}/bundles/stg--api").status_code == 200
    assert viewer.put(f"{V}/bundles/stg--api/keys/api-secret__TOKEN", data={"mode": "update", "value": "x"}).status_code == 403
    assert viewer.get("/api/audit").status_code == 403
    assert viewer.get("/api/users").status_code == 403


def test_editor_write_paths(users, admin):
    editor, _ = users
    b = f"{V}/bundles/stg--web"
    ver = editor.get(b).json()["version"]
    new_val, add_val, file_val = (secrets.token_hex(16) for _ in range(3))

    r = editor.put(f"{b}/keys/web-secret__KEY", data={"mode": "update", "value": new_val, "expect_version": ver})
    assert r.status_code == 200, r.text
    v2 = r.json()["version"]
    assert_no_values(r.text, [new_val])

    stale = editor.put(f"{b}/keys/web-secret__KEY", data={"mode": "update", "value": "zz", "expect_version": ver})
    assert stale.status_code == 409 and "changed meanwhile" in stale.json()["error"]

    same = editor.put(f"{b}/keys/web-secret__KEY", data={"mode": "update", "value": new_val, "expect_version": v2})
    assert same.status_code == 409

    dup = editor.put(f"{b}/keys/web-secret__KEY", data={"mode": "create", "value": "x", "expect_version": v2})
    assert dup.status_code == 409

    missing = editor.put(f"{b}/keys/web-secret__NOPE", data={"mode": "update", "value": "x", "expect_version": v2})
    assert missing.status_code == 409

    bad = editor.put(f"{b}/keys/bad key!", data={"mode": "create", "value": "x"})
    assert bad.status_code in (404, 409)

    r = editor.put(f"{b}/keys/web-secret__NEW", data={"mode": "create", "value": add_val, "expect_version": v2})
    assert r.status_code == 200
    v3 = r.json()["version"]

    r = editor.put(f"{b}/keys/web-secret__CERT", data={"mode": "create", "expect_version": v3},
                   files={"file": ("cert.pem", f"-----BEGIN-----\n{file_val}\n-----END-----\n")})
    assert r.status_code == 200
    v4 = r.json()["version"]

    big = editor.put(f"{b}/keys/web-secret__BIG", data={"mode": "create", "value": "x" * 70000})
    assert big.status_code == 413

    assert editor.post(f"{b}/keys/web-secret__NEW/delete", json={"confirm": "web-secret__NEW", "expect_version": v4}).status_code == 403
    assert admin.post(f"{b}/keys/web-secret__NEW/delete", json={"confirm": "wrong", "expect_version": v4}).status_code == 400
    r = admin.post(f"{b}/keys/web-secret__NEW/delete", json={"confirm": "web-secret__NEW", "expect_version": v4})
    assert r.status_code == 200
    v5 = r.json()["version"]

    keys = editor.get(b).json()["keys"]
    assert "web-secret__CERT" in keys and "web-secret__NEW" not in keys

    diff = editor.get(f"{b}/versions/{v3}/diff").json()
    assert diff == {"added": ["web-secret__NEW"], "removed": [], "changed": []}

    assert editor.post(f"{b}/versions/{ver}/restore", json={"confirm": "x"}).status_code == 400
    r = editor.post(f"{b}/versions/{ver}/restore", json={"confirm": ver})
    assert r.status_code == 200 and int(r.json()["version"]) == int(v5) + 1
    assert editor.get(b).json()["keys"] == ["web-secret__KEY"]

    vers = editor.get(f"{b}/versions").text
    audit = admin.get("/api/audit?limit=100").text
    for text in (vers, audit):
        assert_no_values(text, [new_val, add_val, file_val] + SEEDED)
    assert '"action":"add_key"' in audit.replace(" ", "") and "web-secret__CERT" in audit


def test_reveal_rules(admin, users):
    editor, viewer = users
    k = f"{V}/bundles/stg--api/keys/api-secret__DB_PASSWORD/reveal"
    assert viewer.get("/api/me").json()["can_reveal"] is False
    assert editor.get("/api/me").json()["can_reveal"] is False                         # non-admins never see it
    assert admin.get("/api/me").json()["can_reveal"] is True
    assert viewer.post(k, json={"reason": "debugging login"}).status_code == 403
    assert editor.post(k, json={"reason": "debugging login"}).status_code == 403
    assert admin.post(k, json={"reason": "x"}).status_code == 400                       # reason required
    nocsrf = client("admin@example.com"); del nocsrf.headers["x-csrf-token"]
    assert nocsrf.post(k, json={"reason": "debugging login"}).status_code == 400
    r = admin.post(k, json={"reason": "debugging login"})
    assert r.status_code == 200 and r.json()["value"] == SEEDED[0]
    assert "no-store" in r.headers["cache-control"]
    assert admin.post(f"{V}/bundles/stg--api/keys/nope/reveal", json={"reason": "debugging"}).status_code == 409
    audit = admin.get("/api/audit?limit=20").text
    assert '"reveal_key"' in audit and "debugging login" in audit
    assert_no_values(audit, SEEDED)                                                       # value never audited


def test_version_delete_rules(admin, users):
    editor, viewer = users
    b = f"{V}/bundles/stg--api"
    assert admin.get("/api/vaults").json()[0]["can_destroy_versions"] is True
    cur = admin.get(b).json()["version"]
    new = admin.put(f"{b}/keys/api-secret__TOKEN", data={"mode": "update", "value": secrets.token_hex(8),
                                                         "expect_version": cur}).json()["version"]
    old = cur
    # current version can never be deleted, even by an admin with a correct confirmation
    r = admin.post(f"{b}/versions/{new}/destroy", json={"confirm": new})
    assert r.status_code == 409 and "current version" in r.json()["error"]
    # editors and viewers cannot delete versions at all
    assert editor.post(f"{b}/versions/{old}/destroy", json={"confirm": old}).status_code == 403
    assert viewer.post(f"{b}/versions/{old}/destroy", json={"confirm": old}).status_code == 403
    assert admin.post(f"{b}/versions/{old}/destroy", json={"confirm": "x"}).status_code == 400
    assert admin.post(f"{b}/versions/{old}/destroy", json={"confirm": old}).status_code == 200
    states = {v["id"]: v["state"] for v in admin.get(f"{b}/versions").json()}
    assert states[old] == "destroyed" and states[new] == "enabled"
    assert admin.post(f"{b}/versions/{old}/destroy", json={"confirm": old}).status_code == 409   # already deleted
    assert admin.post(f"{b}/versions/{old}/restore", json={"confirm": old}).status_code == 409   # cannot restore
    assert admin.get(b).json()["version"] == new                                                # current intact
    assert '"delete_version"' in admin.get("/api/audit?limit=20").text


def test_bundle_itself_cannot_be_deleted(admin):
    b = f"{V}/bundles/stg--api"
    for method in ("DELETE", "POST", "PUT"):
        r = admin.request(method, b)
        assert r.status_code in (404, 405), (method, r.status_code)
    assert admin.post(f"{b}/delete", json={"confirm": "stg--api"}).status_code in (404, 405)
    assert admin.post(f"{b}/destroy", json={"confirm": "stg--api"}).status_code in (404, 405)
    assert admin.get(b).status_code == 200


def test_admin_user_rules(admin, users):
    r = admin.put("/api/users", json={"email": "admin@example.com", "role": "editor", "active": True})
    assert r.status_code == 400 and "last active admin" in r.json()["error"]
    assert admin.put("/api/users", json={"email": "x@other.com", "role": "viewer"}).status_code == 400
    assert admin.put("/api/users", json={"email": "y@example.com", "role": "root"}).status_code == 400

    _, viewer = users
    assert admin.put("/api/users", json={"email": "viewer@example.com", "role": "viewer", "active": False}).status_code == 200
    assert viewer.get(f"{V}/bundles").status_code == 401                # deactivation is immediate
    assert client().post("/auth/dev", data={"email": "viewer@example.com"}).status_code == 403
    assert admin.put("/api/users", json={"email": "viewer@example.com", "role": "viewer", "active": True}).status_code == 200


def test_logout(admin):
    c = client("admin@example.com")
    assert c.post("/auth/logout").status_code == 200
    assert c.get(f"{V}/bundles").status_code == 401
