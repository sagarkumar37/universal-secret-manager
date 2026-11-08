"""PostgreSQL access: users/roles and the append-only audit log. Schema lives in /init-migration (never created here).
The app connects as a role that can INSERT/SELECT the audit log but not UPDATE/DELETE it."""
from __future__ import annotations

import json

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

ROLES = ("viewer", "editor", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}


class DB:
    def __init__(self, url: str):
        self.pool = ConnectionPool(url, min_size=1, max_size=5, kwargs={"row_factory": dict_row}, open=True)

    def ping(self) -> bool:
        with self.pool.connection() as c:
            return c.execute("SELECT 1 AS ok").fetchone()["ok"] == 1

    # ---- users ----
    def get_user(self, email: str) -> dict | None:
        with self.pool.connection() as c:
            return c.execute("SELECT email, role, active FROM users WHERE email = %s", (email,)).fetchone()

    def touch_login(self, email: str) -> None:
        with self.pool.connection() as c:
            c.execute("UPDATE users SET last_login = now() WHERE email = %s", (email,))

    def list_users(self) -> list[dict]:
        with self.pool.connection() as c:
            return c.execute("SELECT email, role, active, created_at, created_by, last_login FROM users ORDER BY email").fetchall()

    def upsert_user(self, email: str, role: str, active: bool, by: str) -> None:
        if role not in ROLES:
            raise ValueError("role must be one of " + ", ".join(ROLES))
        with self.pool.connection() as c:
            c.execute("""INSERT INTO users (email, role, active, created_by) VALUES (%s, %s, %s, %s)
                         ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role, active = EXCLUDED.active""",
                      (email, role, active, by))

    def bootstrap_admins(self, emails: list[str]) -> None:
        """Make sure the configured initial admins exist (never downgrades or re-activates an existing user)."""
        with self.pool.connection() as c:
            for e in emails:
                c.execute("""INSERT INTO users (email, role, active, created_by) VALUES (%s, 'admin', true, 'config')
                             ON CONFLICT (email) DO NOTHING""", (e,))

    def count_active_admins(self) -> int:
        with self.pool.connection() as c:
            return c.execute("SELECT count(*) AS n FROM users WHERE role = 'admin' AND active").fetchone()["n"]

    # ---- audit ----
    def audit(self, actor: str, action: str, ok: bool, vault: str | None = None, bundle: str | None = None,
              key: str | None = None, from_version: str | None = None, to_version: str | None = None,
              client_ip: str | None = None, **detail) -> None:
        with self.pool.connection() as c:
            c.execute("""INSERT INTO audit_log (actor, action, ok, vault, bundle, key, from_version, to_version,
                                                client_ip, detail)
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                      (actor, action, ok, vault, bundle, key, from_version, to_version, client_ip,
                       json.dumps(detail, default=str)))

    def list_audit(self, limit: int = 200, bundle: str | None = None, actor: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM audit_log WHERE true", []
        if bundle:
            q += " AND bundle = %s"; args.append(bundle)
        if actor:
            q += " AND actor = %s"; args.append(actor)
        q += " ORDER BY id DESC LIMIT %s"; args.append(min(limit, 2000))
        with self.pool.connection() as c:
            return c.execute(q, args).fetchall()
