"""Vercel entry point. The gateway is built by its own deployment factory, so the
API, CLI and benchmark keep sharing one construction path. Vercel's filesystem is
read-only except the temp directory, so the demo ledger lives there (it resets with
the instance).
"""

import os
import tempfile
from pathlib import Path

from pramana.gateway.app import default_app

LEDGER = Path(tempfile.gettempdir()) / "pramana-ledger.jsonl"
# default_app() reads PRAMANA_LEDGER when called, not when imported.
os.environ.setdefault("PRAMANA_LEDGER", str(LEDGER))

app = default_app()
