"""In-memory vault for tests and local demos."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .base import Bundle, ProviderError, VaultProvider, Version, parse_bundle


class MemoryVault(VaultProvider):
    kind = "memory"
    can_destroy_versions = True

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.store: dict[str, list[dict]] = {}
        for name, data in (cfg.get("seed") or {}).items():
            self.store[name] = [self._ver(json.dumps(data))]

    @staticmethod
    def _ver(raw: str) -> dict:
        return {"t": datetime.now(timezone.utc), "raw": raw, "state": "enabled"}

    def location(self) -> str:
        return "in-memory test vault"

    def list_bundles(self) -> list[Bundle]:
        return [Bundle(name=n, updated=v[-1]["t"]) for n, v in sorted(self.store.items())
                if not self.bundle_filter or self.bundle_filter in n]

    def _read(self, bundle: str, version: str = "latest") -> tuple[dict, str]:
        vers = self.store.get(bundle)
        if not vers:
            raise ProviderError(f"{bundle} not found")
        if version == "latest":
            i = max((n for n, v in enumerate(vers, 1) if v["state"] == "enabled"), default=0)
        else:
            i = int(version) if version.isdigit() else 0
        if not 1 <= i <= len(vers) or vers[i - 1]["state"] != "enabled":
            raise ProviderError(f"{bundle} version {version} not found or not readable")
        return parse_bundle(vers[i - 1]["raw"], bundle), str(i)

    def _write(self, bundle: str, data: dict) -> str:
        self.store[bundle].append(self._ver(json.dumps(data)))
        return str(len(self.store[bundle]))

    def versions(self, bundle: str) -> list[Version]:
        self.check_bundle(bundle)
        return [Version(id=str(i), created=v["t"], state=v["state"])
                for i, v in reversed(list(enumerate(self.store[bundle], 1)))]

    def _destroy(self, bundle: str, version: str) -> None:
        v = self.store[bundle][int(version) - 1]
        v["state"], v["raw"] = "destroyed", ""
