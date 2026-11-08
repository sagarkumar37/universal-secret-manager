"""Azure Key Vault (needs azure-identity, azure-keyvault-secrets; auth via DefaultAzureCredential)."""
from __future__ import annotations

import json

from .base import Bundle, ProviderError, VaultProvider, Version, parse_bundle


class AzureKeyVault(VaultProvider):
    kind = "azure"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError:
            raise ProviderError("azure provider needs: pip install azure-identity azure-keyvault-secrets")
        self.vault_url = cfg["vault_url"]
        self.client = SecretClient(vault_url=self.vault_url, credential=DefaultAzureCredential())

    def location(self) -> str:
        return f"Azure Key Vault {self.vault_url}"

    def list_bundles(self) -> list[Bundle]:
        out = [Bundle(name=p.name, updated=p.updated_on) for p in self.client.list_properties_of_secrets()
               if not self.bundle_filter or self.bundle_filter in p.name]
        return sorted(out, key=lambda b: b.name)

    def _read(self, bundle: str, version: str = "latest") -> tuple[dict, str]:
        s = self.client.get_secret(bundle, None if version == "latest" else version)
        return parse_bundle(s.value, bundle), s.properties.version

    def _write(self, bundle: str, data: dict) -> str:
        s = self.client.set_secret(bundle, json.dumps(data, sort_keys=True), content_type="application/json")
        return s.properties.version

    def versions(self, bundle: str) -> list[Version]:
        self.check_bundle(bundle)
        out = [Version(id=p.version, created=p.created_on, state="enabled" if p.enabled else "disabled")
               for p in self.client.list_properties_of_secret_versions(bundle)]
        return sorted(out, key=lambda v: v.created or 0, reverse=True)
