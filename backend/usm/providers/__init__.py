"""Provider registry: add a vault type here."""
from .base import ProviderError, VaultProvider

PROVIDERS = {
    "gcp": ("usm.providers.gcp", "GCPSecretManager"),
    "azure": ("usm.providers.azure", "AzureKeyVault"),
    "aws": ("usm.providers.aws", "AWSSecretsManager"),
    "memory": ("usm.providers.memory", "MemoryVault"),
}


def make_provider(cfg: dict) -> VaultProvider:
    kind = cfg.get("provider")
    if kind not in PROVIDERS:
        raise ProviderError(f"unknown provider '{kind}' (known: {', '.join(PROVIDERS)})")
    import importlib
    mod, cls = PROVIDERS[kind]
    return getattr(importlib.import_module(mod), cls)(cfg.get(kind) or {})


__all__ = ["make_provider", "ProviderError", "VaultProvider"]
