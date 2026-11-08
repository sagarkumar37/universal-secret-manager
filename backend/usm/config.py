"""Configuration: non-secret settings from a YAML file (USM_CONFIG), secrets ONLY from environment variables
(USM_SESSION_KEY, USM_GOOGLE_CLIENT_SECRET, DATABASE_URL) or *_FILE variants pointing at files (Docker/K8s secrets)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def env_secret(name: str, required: bool = True) -> str:
    """Read NAME, or the file named by NAME_FILE."""
    if os.environ.get(f"{name}_FILE"):
        return Path(os.environ[f"{name}_FILE"]).read_text().strip()
    val = os.environ.get(name, "")
    if required and not val:
        raise SystemExit(f"missing required secret {name} (or {name}_FILE)")
    return val


@dataclass
class Settings:
    instance_name: str
    banner: str
    base_url: str
    google_client_id: str
    allowed_domains: list[str]
    initial_admins: list[str]
    session_hours: int
    dev_login: bool
    vaults: list[dict]
    max_value_bytes: int
    reveal_role: str            # "none" (default) | viewer | editor | admin - who may view a secret value
    reveal_seconds: int
    session_key: str = field(repr=False, default="")
    google_client_secret: str = field(repr=False, default="")
    database_url: str = field(repr=False, default="")


def load() -> Settings:
    raw = yaml.safe_load(Path(os.environ.get("USM_CONFIG", "/etc/usm/config.yaml")).read_text())
    inst, auth = raw.get("instance", {}), raw.get("auth", {})
    vaults = raw.get("vaults") or []
    if not vaults:
        raise SystemExit("config: at least one vault under 'vaults:'")
    ids = [v.get("id") for v in vaults]
    if len(set(ids)) != len(ids) or not all(ids):
        raise SystemExit("config: every vault needs a unique 'id'")
    dev = bool(auth.get("dev_login"))
    if dev and any(v.get("provider") != "memory" for v in vaults):
        raise SystemExit("config: dev_login is only allowed when every vault uses provider 'memory' (testing)")
    s = Settings(
        instance_name=inst.get("name", "usm"),
        banner=inst.get("banner", inst.get("name", "usm")),
        base_url=inst["base_url"].rstrip("/"),
        google_client_id=auth.get("google_client_id", ""),
        allowed_domains=[d.lower() for d in auth.get("allowed_domains") or []],
        initial_admins=[e.lower() for e in auth.get("initial_admins") or []],
        session_hours=int(auth.get("session_hours", 8)),
        dev_login=dev,
        vaults=vaults,
        max_value_bytes=int((raw.get("limits") or {}).get("max_value_bytes", 64 * 1024)),
        reveal_role=str((raw.get("reveal") or {}).get("role", "none")).lower(),
        reveal_seconds=int((raw.get("reveal") or {}).get("seconds", 30)),
    )
    if s.reveal_role not in ("none", "viewer", "editor", "admin"):
        raise SystemExit("config: reveal.role must be none, viewer, editor or admin")
    if not s.allowed_domains:
        raise SystemExit("config: auth.allowed_domains must list at least one Google Workspace domain")
    s.session_key = env_secret("USM_SESSION_KEY")
    s.database_url = env_secret("DATABASE_URL")
    if not dev:
        if not s.google_client_id:
            raise SystemExit("config: auth.google_client_id is required")
        s.google_client_secret = env_secret("USM_GOOGLE_CLIENT_SECRET")
    return s
