"""Vault provider interface. A bundle = one vault secret holding a JSON object of key -> string value."""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")


class ProviderError(Exception):
    """Shown to users as-is - must never contain a secret value."""


@dataclass
class Bundle:
    name: str
    updated: datetime | None = None


@dataclass
class Version:
    id: str
    created: datetime | None
    state: str            # enabled / disabled / destroyed
    keys: int | None = None


class VaultProvider(ABC):
    kind = "abstract"
    can_destroy_versions = False      # providers that can permanently delete a single old version set this

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.bundle_filter = cfg.get("bundle_filter", "")   # e.g. "--": only bundles named <env>--<group>

    # ---- what each vault implements -------------------------------------------------------------------------
    @abstractmethod
    def location(self) -> str:
        """Human label of the vault, e.g. 'GCP Secret Manager, project my-project'."""

    @abstractmethod
    def list_bundles(self) -> list[Bundle]: ...

    @abstractmethod
    def _read(self, bundle: str, version: str = "latest") -> tuple[dict, str]:
        """Return (json dict, version id). Internal only."""

    @abstractmethod
    def _write(self, bundle: str, data: dict) -> str:
        """Store `data` as the new current value of the bundle; return the new version id."""

    @abstractmethod
    def versions(self, bundle: str) -> list[Version]: ...

    def _destroy(self, bundle: str, version: str) -> None:
        raise ProviderError("this vault does not support deleting single versions")

    # There is deliberately NO way to delete a whole bundle (secret) through this interface.

    # ---- shared logic (same for every vault) ----------------------------------------------------------------
    def check_bundle(self, bundle: str) -> None:
        if self.bundle_filter and self.bundle_filter not in bundle:
            raise ProviderError(f"'{bundle}' is not a managed bundle")

    def list_keys(self, bundle: str) -> tuple[list[str], str]:
        self.check_bundle(bundle)
        data, ver = self._read(bundle)
        return sorted(data), ver

    def reveal(self, bundle: str, key: str) -> tuple[str, str]:
        """The ONLY method that returns a value. Callers must check permission and audit it."""
        self.check_bundle(bundle)
        data, ver = self._read(bundle)
        if key not in data:
            raise ProviderError(f"key '{key}' does not exist in {bundle}")
        return data[key], ver

    def set_key(self, bundle: str, key: str, value: str, *, must_exist: bool | None, expect_version: str | None) -> str:
        """expect_version: refuse if the bundle changed since the caller read it."""
        self.check_bundle(bundle)
        if not KEY_RE.match(key):
            raise ProviderError("key name: letters, digits, _ . - only (max 200)")
        if value == "":
            raise ProviderError("empty value - use 'Delete key' to remove a key")
        data, ver = self._read(bundle)
        if expect_version and ver != expect_version:
            raise ProviderError(f"bundle changed meanwhile (now version {ver}, you opened {expect_version}) - reload and retry")
        if must_exist is True and key not in data:
            raise ProviderError(f"key '{key}' does not exist in {bundle}")
        if must_exist is False and key in data:
            raise ProviderError(f"key '{key}' already exists in {bundle} - use Update")
        if data.get(key) == value:
            raise ProviderError("the new value is the same as the current one - nothing changed")
        data[key] = value
        return self._write(bundle, data)

    def delete_key(self, bundle: str, key: str, *, expect_version: str | None) -> str:
        self.check_bundle(bundle)
        data, ver = self._read(bundle)
        if expect_version and ver != expect_version:
            raise ProviderError(f"bundle changed meanwhile (now version {ver}) - reload and retry")
        if key not in data:
            raise ProviderError(f"key '{key}' does not exist in {bundle}")
        del data[key]
        return self._write(bundle, data)

    def restore_version(self, bundle: str, version: str) -> str:
        """Make an old version current again (as a NEW version - history is never rewritten)."""
        self.check_bundle(bundle)
        data, _ = self._read(bundle, version)
        return self._write(bundle, data)

    def destroy_version(self, bundle: str, version: str) -> None:
        """Permanently delete one OLD version. The version workloads read now (latest) can never be deleted."""
        self.check_bundle(bundle)
        if not self.can_destroy_versions:
            raise ProviderError("this vault does not support deleting single versions")
        v = next((x for x in self.versions(bundle) if x.id == version), None)
        if v is None:
            raise ProviderError(f"version {version} of {bundle} not found")
        if v.state == "destroyed":
            raise ProviderError(f"version {version} is already deleted")
        _, current = self._read(bundle)             # resolved at the moment of the request, not from the page
        if version == current:
            raise ProviderError(f"version {version} is the current version that workloads read - it can never be deleted")
        self._destroy(bundle, version)

    def key_diff(self, bundle: str, version: str) -> tuple[list[str], list[str], list[str]]:
        """Keys (names only) added / removed / changed between `version` and its predecessor."""
        self.check_bundle(bundle)
        new, _ = self._read(bundle, version)
        vers = [v.id for v in self.versions(bundle) if v.state != "destroyed"]
        older = [v for v in vers if _num(v) < _num(version)]
        old = self._read(bundle, max(older, key=_num))[0] if older else {}
        added = sorted(set(new) - set(old))
        removed = sorted(set(old) - set(new))
        changed = sorted(k for k in set(new) & set(old) if new[k] != old[k])
        return added, removed, changed


def _num(v: str) -> int:
    try:
        return int(v)
    except ValueError:
        return 0


def parse_bundle(raw: bytes | str, bundle: str) -> dict:
    try:
        data = json.loads(raw)
    except Exception:
        raise ProviderError(f"{bundle} is not a JSON bundle - manage it in the vault console")
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ProviderError(f"{bundle} is not a flat JSON object of strings - manage it in the vault console")
    return data
