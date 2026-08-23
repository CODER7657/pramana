"""HTTP surface over the kernel.

This module contains **no decision logic**. Every request is converted into a
:class:`~pramana.kernel.gate.PaymentRequest`, handed to ``Kernel.evaluate``, and
converted back. If a rule appears here that is not in the kernel, that is a bug:
the whole point of the facade is that the CLI, the benchmark and this API cannot
disagree about what is authorised.

Status codes fail closed
------------------------

    200  ALLOW
    403  REJECT   -- with the full verdict in the body
    400  malformed request, no decision reached
    500  internal error, no decision reached

An integrator who checks only ``response.ok`` and ignores the body gets the
right answer. This is deliberate and it is the reason ``REJECT`` is not 200.

Returning 200-with-``decision: reject`` is arguably more RESTful -- the
evaluation *did* succeed, the payment merely was not authorised -- but it makes
the careless integration fail **open**, which is the one failure mode this
project exists to prevent. Correct REST semantics are not worth an unauthorised
payment. The ``decision`` field remains authoritative for anyone who reads it.

For the same reason, 400 and 500 responses carry no ``decision`` field at all.
There is nothing there for a careless caller to misread as permission.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Final

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pramana import __version__
from pramana.gateway.models import (
    ErrorResponse,
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
)
from pramana.kernel.gate import Kernel, PaymentRequest
from pramana.kernel.trace import TraceContext
from pramana.kernel.verify.rbi import PaymentFacts

logger = logging.getLogger(__name__)

TRACEPARENT_HEADER: Final = "traceparent"
ELAPSED_HEADER: Final = "x-pramana-elapsed-ms"
DECISION_HEADER: Final = "x-pramana-decision"
POLICY_HEADER: Final = "x-pramana-policy-version"


def _to_payment_request(
    body: EvaluateRequest, traceparent: str | None
) -> PaymentRequest:
    """Edge -> kernel. The only place wire types are unwrapped."""
    return PaymentRequest(
        mandate_ref=body.mandate_ref,
        facts=PaymentFacts(
            amount_paise=body.facts.amount_paise,
            currency=body.facts.currency,
            category=body.facts.category,
            afa_performed=body.facts.afa_performed,
            afa_at_registration=body.facts.afa_at_registration,
            pre_debit_notice_at=body.facts.pre_debit_notice_at,
            execution_at=body.facts.execution_at,
            mandate_valid_from=body.facts.mandate_valid_from,
            mandate_valid_until=body.facts.mandate_valid_until,
        ),
        protocol_results=tuple(o.to_obligation() for o in body.protocol_obligations),
        mandate_results=tuple(o.to_obligation() for o in body.mandate_obligations),
        merchant_results=tuple(o.to_obligation() for o in body.merchant_obligations),
        risk_context=body.risk_context,
        traceparent=traceparent,
    )


def create_app(kernel: Kernel) -> FastAPI:
    """Build the API around an already-constructed kernel.

    The kernel is injected rather than built here so that tests, the benchmark
    and a deployment all share one construction path.
    """
    app = FastAPI(
        title="PRAMANA",
        version=__version__,
        description=(
            "Deterministic verification gate for agent-initiated payments. "
            "200 = allow, 403 = reject. A status-only integration fails closed."
        ),
    )
    app.state.kernel = kernel

    # -- middleware --------------------------------------------------------

    @app.middleware("http")
    async def _propagate_trace(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Echo the trace back so a caller can correlate without parsing a body."""
        response = await call_next(request)
        inbound = request.headers.get(TRACEPARENT_HEADER)
        if inbound and TRACEPARENT_HEADER not in response.headers:
            response.headers[TRACEPARENT_HEADER] = inbound
        return response

    # -- error handling ----------------------------------------------------

    @app.exception_handler(RequestValidationError)
    async def _on_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """A malformed request has no verdict, and says so."""
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg', '')}"
            for e in exc.errors()[:5]
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error="invalid_request",
                detail=problems or "request failed validation",
                trace_id=_trace_of(request),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def _on_unexpected(request: Request, exc: Exception) -> JSONResponse:
        """Never leak internals, and never imply a decision was reached."""
        incident = uuid.uuid4().hex[:12]
        logger.exception("unhandled gateway error [incident=%s]", incident)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="internal_error",
                detail=(
                    f"The request could not be evaluated. No decision was "
                    f"reached. Incident {incident}."
                ),
                trace_id=_trace_of(request),
            ).model_dump(),
        )

    # -- routes ------------------------------------------------------------

    @app.post(
        "/v1/evaluate",
        response_model=EvaluateResponse,
        responses={
            200: {"description": "Authorised."},
            403: {"description": "Not authorised. The verdict is in the body."},
            400: {"model": ErrorResponse, "description": "Malformed request."},
        },
        summary="Evaluate one agent-initiated payment",
    )
    async def evaluate(body: EvaluateRequest, request: Request) -> Response:
        result = request.app.state.kernel.evaluate(
            _to_payment_request(body, request.headers.get(TRACEPARENT_HEADER))
        )
        payload = EvaluateResponse.from_result(result)
        return JSONResponse(
            status_code=(
                status.HTTP_200_OK if result.is_allowed
                else status.HTTP_403_FORBIDDEN
            ),
            content=payload.model_dump(),
            headers={
                TRACEPARENT_HEADER: result.trace.traceparent(),
                DECISION_HEADER: payload.decision,
                POLICY_HEADER: payload.policy_version,
                ELAPSED_HEADER: f"{result.elapsed_ms:.3f}",
            },
        )

    @app.get("/health", response_model=HealthResponse, summary="Liveness and config")
    async def health(request: Request) -> HealthResponse:
        k: Kernel = request.app.state.kernel
        return HealthResponse(
            status="ok",
            version=__version__,
            policy_version=k.policy.version,
            declared_obligations=len(k.policy.declared_ids),
            ledger_records=len(k.ledger) if k.ledger is not None else None,
            risk_adapters=[getattr(a, "name", "?") for a in k.risk_adapters],
        )

    @app.get("/v1/policy", summary="The policy in force")
    async def policy(request: Request) -> dict[str, Any]:
        """Exposed deliberately.

        A merchant subject to this gate is entitled to read the rules it is
        being held to, including the provision behind every regulatory one.
        A policy nobody can inspect is not a policy, it is a black box -- which
        is the thing we argue against.
        """
        k: Kernel = request.app.state.kernel
        return k.policy.to_dict()

    return app


def _trace_of(request: Request) -> str | None:
    inbound = request.headers.get(TRACEPARENT_HEADER)
    if not inbound:
        return None
    parsed = TraceContext.parse(inbound)
    return parsed.trace_id if parsed else None
