"""Schema-driven contract test: no route may ever answer with a 5xx.

The OpenAPI schema is loaded from the app in-process (ASGI, no network, no
sockets) and Schemathesis generates requests from it. The only property
asserted is that the gate never fails *open or crashed*: any generated input
must produce a 2xx or 4xx, never an unhandled 5xx.

This generates inputs against this project's own in-memory app only; it is a
robustness check on the gate's own input handling.
"""

from __future__ import annotations

import schemathesis
from hypothesis import HealthCheck, settings

from pramana.gateway.app import create_app
from pramana.kernel.gate import Kernel
from pramana.kernel.ledger.chain_log import EvidenceLedger, MemoryStore
from pramana.kernel.verify.policy import builtin_policy

app = create_app(Kernel(builtin_policy(), ledger=EvidenceLedger(MemoryStore())))
schema = schemathesis.openapi.from_asgi("/openapi.json", app)


def test_schema_exposes_routes() -> None:
    """Guard against a vacuous pass: the fuzz below must have routes to hit."""
    operations = list(schema.get_all_operations())
    assert len(operations) >= 2


@schema.parametrize()
@settings(
    max_examples=25,
    deadline=None,
    derandomize=True,
    suppress_health_check=list(HealthCheck),
)
def test_no_route_returns_5xx(case: schemathesis.Case) -> None:
    response = case.call()
    assert response.status_code < 500, (
        f"{case.method} {case.path} -> {response.status_code}: {response.text[:200]}"
    )
