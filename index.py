"""Vercel entry point. The gateway is built by its own deployment factory, so the
API, CLI and benchmark keep sharing one construction path. Vercel's filesystem is
read-only except /tmp, so the demo ledger lives there (it resets with the instance).
"""

import os

os.environ.setdefault("PRAMANA_LEDGER", "/tmp/pramana-ledger.jsonl")

from pramana.gateway.app import default_app  # noqa: E402

app = default_app()
