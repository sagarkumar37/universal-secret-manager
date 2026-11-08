"""AWS Secrets Manager (needs boto3; standard AWS credential chain)."""
from __future__ import annotations

import json

from .base import Bundle, ProviderError, VaultProvider, Version, parse_bundle


class AWSSecretsManager(VaultProvider):
    kind = "aws"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        try:
            import boto3
        except ImportError:
            raise ProviderError("aws provider needs: pip install boto3")
        self.region = cfg["region"]
        self.client = boto3.client("secretsmanager", region_name=self.region)

    def location(self) -> str:
        return f"AWS Secrets Manager, region {self.region}"

    def list_bundles(self) -> list[Bundle]:
        out = []
        for page in self.client.get_paginator("list_secrets").paginate():
            for s in page["SecretList"]:
                if not self.bundle_filter or self.bundle_filter in s["Name"]:
                    out.append(Bundle(name=s["Name"], updated=s.get("LastChangedDate")))
        return sorted(out, key=lambda b: b.name)

    def _read(self, bundle: str, version: str = "latest") -> tuple[dict, str]:
        kw = {"SecretId": bundle}
        if version != "latest":
            kw["VersionId"] = version
        r = self.client.get_secret_value(**kw)
        return parse_bundle(r["SecretString"], bundle), r["VersionId"]

    def _write(self, bundle: str, data: dict) -> str:
        r = self.client.put_secret_value(SecretId=bundle, SecretString=json.dumps(data, sort_keys=True))
        return r["VersionId"]

    def versions(self, bundle: str) -> list[Version]:
        self.check_bundle(bundle)
        r = self.client.list_secret_version_ids(SecretId=bundle, IncludeDeprecated=False)
        out = [Version(id=v["VersionId"], created=v.get("CreatedDate"),
                       state="current" if "AWSCURRENT" in v.get("VersionStages", []) else "previous")
               for v in r["Versions"]]
        return sorted(out, key=lambda v: v.created or 0, reverse=True)
