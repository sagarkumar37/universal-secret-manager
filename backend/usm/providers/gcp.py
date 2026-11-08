"""GCP Secret Manager."""
from __future__ import annotations

import json

from google.api_core import exceptions as gexc
from google.cloud import secretmanager
from google.oauth2 import service_account

from .base import Bundle, ProviderError, VaultProvider, Version, parse_bundle


class GCPSecretManager(VaultProvider):
    kind = "gcp"
    can_destroy_versions = True

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.project = cfg["project"]
        creds = None
        if cfg.get("credentials_file"):
            path = cfg["credentials_file"]
            try:
                with open(path) as f:
                    empty = not f.read(1)
            except OSError:
                raise ProviderError(f"GCP credentials file {path} not found")
            if empty:
                raise ProviderError(f"GCP credentials file {path} is empty - add the service-account JSON key")
            creds = service_account.Credentials.from_service_account_file(path)
        self.client = secretmanager.SecretManagerServiceClient(credentials=creds)
        self.parent = f"projects/{self.project}"

    def location(self) -> str:
        return f"GCP Secret Manager, project {self.project}"

    def _name(self, bundle: str) -> str:
        return f"{self.parent}/secrets/{bundle}"

    def list_bundles(self) -> list[Bundle]:
        try:
            out = []
            for s in self.client.list_secrets(request={"parent": self.parent}):
                name = s.name.rsplit("/", 1)[-1]
                if self.bundle_filter and self.bundle_filter not in name:
                    continue
                out.append(Bundle(name=name, updated=None))
            return sorted(out, key=lambda b: b.name)
        except gexc.GoogleAPICallError as e:
            raise ProviderError(f"GCP: {e.message}")

    def _read(self, bundle: str, version: str = "latest") -> tuple[dict, str]:
        try:
            r = self.client.access_secret_version(request={"name": f"{self._name(bundle)}/versions/{version}"})
        except gexc.NotFound:
            raise ProviderError(f"{bundle} (version {version}) not found")
        except gexc.GoogleAPICallError as e:
            raise ProviderError(f"GCP: {e.message}")
        return parse_bundle(r.payload.data, bundle), r.name.rsplit("/", 1)[-1]

    def _write(self, bundle: str, data: dict) -> str:
        payload = json.dumps(data, indent=None, sort_keys=True).encode()
        try:
            v = self.client.add_secret_version(request={"parent": self._name(bundle), "payload": {"data": payload}})
        except gexc.GoogleAPICallError as e:
            raise ProviderError(f"GCP: {e.message}")
        return v.name.rsplit("/", 1)[-1]

    def versions(self, bundle: str) -> list[Version]:
        self.check_bundle(bundle)
        try:
            out = []
            for v in self.client.list_secret_versions(request={"parent": self._name(bundle)}):
                out.append(Version(id=v.name.rsplit("/", 1)[-1], created=v.create_time,
                                   state=secretmanager.SecretVersion.State(v.state).name.lower()))
            return sorted(out, key=lambda v: int(v.id), reverse=True)
        except gexc.GoogleAPICallError as e:
            raise ProviderError(f"GCP: {e.message}")

    def _destroy(self, bundle: str, version: str) -> None:
        # needs roles/secretmanager.secretVersionManager (cannot delete secrets themselves)
        try:
            self.client.destroy_secret_version(request={"name": f"{self._name(bundle)}/versions/{version}"})
        except gexc.PermissionDenied:
            raise ProviderError("not allowed: the vault account needs roles/secretmanager.secretVersionManager")
        except gexc.GoogleAPICallError as e:
            raise ProviderError(f"GCP: {e.message}")
