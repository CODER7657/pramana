"""Local configuration: a minimal ``.env`` loader and provider status.

Deliberately dependency-free. `python-dotenv` would be a fine choice in most
projects, but this is a payment verification system and every dependency is a
supply-chain surface (see ADR-0002 for why that is not theoretical here). The
loader is twenty lines and does exactly what we need.

Environment variables that are already set always win over the file, so a CI
secret or a shell export is never silently overridden by a stale local file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pramana.ai.provider import DEFAULT_CHAIN, ProviderConfig

DEFAULT_ENV_FILE = ".env"


def load_dotenv(path: Path | str = DEFAULT_ENV_FILE, *, override: bool = False) -> int:
    """Load ``KEY=value`` pairs from a file into ``os.environ``.

    Returns the number of variables set. Missing file is not an error -- the
    whole system is designed to run without credentials.
    """
    file = Path(path)
    if not file.is_file():
        return 0

    loaded = 0
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    name: str
    env_var: str
    configured: bool
    model: str
    notes: str

    @property
    def marker(self) -> str:
        return "ready" if self.configured else "no key"


def provider_status(
    providers: tuple[ProviderConfig, ...] = DEFAULT_CHAIN,
) -> tuple[ProviderStatus, ...]:
    """Report which providers have a credential present.

    Never returns or logs the key itself, only whether one is set.
    """
    return tuple(
        ProviderStatus(
            name=p.name,
            env_var=p.api_key_env,
            configured=p.api_key() is not None,
            model=p.model,
            notes=p.notes,
        )
        for p in providers
    )
