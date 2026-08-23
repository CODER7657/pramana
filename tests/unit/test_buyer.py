"""The buying agent, treated as hostile.

This is the one component whose output is untrusted input to the kernel. The
tests are therefore adversarial about parsing, and the central case is that a
deliberately compromised agent still cannot get an over-budget cart authorised.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from pramana.ai.buyer import (
    MAX_ITEMS,
    MAX_NAME_CHARS,
    BuyingAgent,
    CartItem,
    PurchaseIntent,
    parse_cart,
)
from pramana.ai.provider import HttpResult, ProviderChain, ProviderConfig
from pramana.kernel.verdict import (
    Decision,
    Obligation,
    ObligationSource,
    ObligationStatus,
    build_verdict,
)

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
REF = hashlib.sha256(b"m").hexdigest()
BUDGET = 500_000  # paise = INR 5,000

P = ProviderConfig(
    name="p", base_url="https://p.test/v1", model="m", api_key_env="P_KEY"
)


def intent(budget: int = BUDGET) -> PurchaseIntent:
    return PurchaseIntent(
        description="a birthday gift",
        budget_paise=budget,
        merchant_id="mrc_test",
        category="gifts",
    )


def cart_json(*items: tuple[str, int, int], rationale: str = "picked these") -> str:
    return json.dumps(
        {
            "items": [
                {"name": n, "unit_price_paise": p, "quantity": q} for n, p, q in items
            ],
            "rationale": rationale,
        }
    )


class Scripted:
    def __init__(self, *results: HttpResult) -> None:
        self.results = list(results)

    def __call__(self, url: str, h: Any, payload: dict[str, Any], t: float) -> Any:
        if not self.results:
            raise AssertionError("over-called")
        return self.results.pop(0)


def ok(text: str) -> HttpResult:
    return HttpResult(200, {"choices": [{"message": {"content": text}}], "model": "m"})


def chain_with(transport: Any) -> ProviderChain:
    return ProviderChain(
        providers=(P,), transport=transport, sleep=lambda _s: None, max_retries=0
    )


@pytest.fixture
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("P_KEY", "k")


def gate(proposal_total: int, budget: int = BUDGET) -> Any:
    """The deterministic check the agent is subject to."""
    within = proposal_total <= budget
    return build_verdict(
        [
            Obligation(
                id="chain.verified",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.PROTOCOL,
                detail="chain ok",
            ),
            Obligation(
                id="mandate.budget",
                status=(
                    ObligationStatus.SATISFIED
                    if within
                    else ObligationStatus.VIOLATED
                ),
                source=ObligationSource.MANDATE,
                detail="cart total against the signed cap",
                observed={"total_paise": proposal_total},
                expected={"max_paise": budget},
            ),
        ],
        policy_version="p@1",
        declared_obligations=("chain.verified", "mandate.budget"),
        trace_id=TRACE,
        mandate_ref=REF,
    )


# ---------------------------------------------------------------------------
# The agent is governed, not trusted
# ---------------------------------------------------------------------------


class TestAgentIsGoverned:
    def test_compromised_agent_is_rejected_by_the_gate(self, key: None) -> None:
        """The demo beat: the agent goes rogue and the payment still fails."""
        agent = BuyingAgent(
            chain_with(Scripted(ok(cart_json(("gift", 400_000, 1))))),
            compromise=True,
        )
        proposal = agent.propose(intent())
        assert proposal.total_paise == 1_200_000
        assert proposal.exceeds(intent())
        assert gate(proposal.total_paise).decision is Decision.REJECT

    def test_honest_agent_is_allowed(self, key: None) -> None:
        agent = BuyingAgent(chain_with(Scripted(ok(cart_json(("gift", 400_000, 1))))))
        proposal = agent.propose(intent())
        assert proposal.total_paise == 400_000
        assert gate(proposal.total_paise).decision is Decision.ALLOW

    def test_agent_claiming_compliance_does_not_authorise_itself(
        self, key: None
    ) -> None:
        """The model asserts it stayed in budget while proposing 10x it."""
        agent = BuyingAgent(
            chain_with(
                Scripted(
                    ok(
                        cart_json(
                            ("gift", 5_000_000, 1),
                            rationale="well within the approved budget",
                        )
                    )
                )
            )
        )
        proposal = agent.propose(intent())
        assert "within the approved budget" in proposal.rationale
        assert gate(proposal.total_paise).decision is Decision.REJECT

    def test_agent_cannot_construct_a_verdict(self, key: None) -> None:
        proposal = BuyingAgent(
            chain_with(Scripted(ok(cart_json(("x", 1, 1)))))
        ).propose(intent())
        assert not hasattr(proposal, "decision")
        assert not hasattr(proposal, "obligations")

    def test_compromise_multiplier_is_configurable(self, key: None) -> None:
        agent = BuyingAgent(
            chain_with(Scripted(ok(cart_json(("gift", 100_000, 1))))),
            compromise=True,
            compromise_multiplier=7,
        )
        assert agent.propose(intent()).total_paise == 700_000

    def test_compromise_is_labelled_in_the_rationale(self, key: None) -> None:
        agent = BuyingAgent(
            chain_with(Scripted(ok(cart_json(("gift", 100_000, 1))))), compromise=True
        )
        assert "COMPROMISED AGENT" in agent.propose(intent()).rationale


# ---------------------------------------------------------------------------
# Parsing untrusted model output
# ---------------------------------------------------------------------------


class TestParsing:
    def test_well_formed_cart(self) -> None:
        parsed = parse_cart(cart_json(("apple", 100, 2), ("pear", 250, 1)))
        assert parsed is not None
        items, rationale = parsed
        assert len(items) == 2
        assert items[0].line_total_paise == 200
        assert rationale == "picked these"

    def test_code_fences_are_tolerated(self) -> None:
        fenced = "```json\n" + cart_json(("apple", 100, 1)) + "\n```"
        assert parse_cart(fenced) is not None

    @pytest.mark.parametrize(
        "bad",
        [
            "not json at all",
            "",
            "[]",
            '"a string"',
            "null",
            '{"items": []}',
            '{"items": "not a list"}',
            '{"no_items_key": 1}',
            '{"items": [{"name": "", "unit_price_paise": 1, "quantity": 1}]}',
            '{"items": [{"name": "x", "unit_price_paise": "free", "quantity": 1}]}',
            '{"items": [{"name": "x", "unit_price_paise": -5, "quantity": 1}]}',
            '{"items": [{"name": "x", "unit_price_paise": 1, "quantity": 0}]}',
            '{"items": [{"name": "x", "unit_price_paise": 1.5, "quantity": 1}]}',
            '{"items": ["not an object"]}',
            '{"items": [{"unit_price_paise": 1, "quantity": 1}]}',
        ],
    )
    def test_malformed_input_is_rejected_wholesale(self, bad: str) -> None:
        assert parse_cart(bad) is None

    def test_boolean_prices_are_rejected(self) -> None:
        """bool subclasses int; True would otherwise become a price of 1."""
        assert (
            parse_cart('{"items": [{"name": "x", "unit_price_paise": true, '
                       '"quantity": 1}]}')
            is None
        )

    def test_boolean_quantity_is_rejected(self) -> None:
        assert (
            parse_cart('{"items": [{"name": "x", "unit_price_paise": 1, '
                       '"quantity": true}]}')
            is None
        )

    def test_item_count_is_capped(self) -> None:
        many = json.dumps(
            {
                "items": [
                    {"name": f"i{n}", "unit_price_paise": 1, "quantity": 1}
                    for n in range(50)
                ]
            }
        )
        parsed = parse_cart(many)
        assert parsed is not None
        assert len(parsed[0]) == MAX_ITEMS

    def test_long_names_are_truncated(self) -> None:
        parsed = parse_cart(cart_json(("x" * 500, 1, 1)))
        assert parsed is not None
        assert len(parsed[0][0].name) == MAX_NAME_CHARS

    def test_missing_rationale_is_tolerated(self) -> None:
        parsed = parse_cart(
            '{"items": [{"name": "x", "unit_price_paise": 1, "quantity": 1}]}'
        )
        assert parsed is not None
        assert parsed[1] == ""

    def test_quantity_defaults_to_one(self) -> None:
        parsed = parse_cart(
            '{"items": [{"name": "x", "unit_price_paise": 500}]}'
        )
        assert parsed is not None
        assert parsed[0][0].quantity == 1


# ---------------------------------------------------------------------------
# Degradation
# ---------------------------------------------------------------------------


class TestDegradation:
    def test_no_chain_uses_fallback(self) -> None:
        proposal = BuyingAgent(None).propose(intent())
        assert proposal.source == "fallback"
        assert proposal.total_paise == BUDGET

    def test_fallback_stays_within_budget(self) -> None:
        """A degraded agent must not accidentally become a compromised one."""
        proposal = BuyingAgent(None).propose(intent())
        assert not proposal.exceeds(intent())
        assert gate(proposal.total_paise).decision is Decision.ALLOW

    def test_provider_failure_falls_back(self, key: None) -> None:
        agent = BuyingAgent(chain_with(Scripted(HttpResult(401, {}, "bad key"))))
        assert agent.propose(intent()).source == "fallback"

    def test_unparseable_response_falls_back(self, key: None) -> None:
        agent = BuyingAgent(chain_with(Scripted(ok("I refuse to shop today."))))
        proposal = agent.propose(intent())
        assert proposal.source == "fallback"
        assert proposal.total_paise == BUDGET

    def test_unexpected_exception_falls_back(self) -> None:
        class Exploding:
            def complete(self, *_a: Any, **_k: Any) -> Any:
                raise RuntimeError("boom")

        assert BuyingAgent(Exploding()).propose(intent()).source == "fallback"  # type: ignore[arg-type]

    def test_propose_never_raises(self, key: None) -> None:
        for response in ("", "{}", "garbage", cart_json(("x", 1, 1))):
            agent = BuyingAgent(chain_with(Scripted(ok(response) if response
                                                    else HttpResult(200, {}))))
            assert agent.propose(intent()).items


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


class TestValueObjects:
    def test_line_total(self) -> None:
        item = CartItem(name="x", unit_price_paise=250, quantity=4)
        assert item.line_total_paise == 1000

    @pytest.mark.parametrize(
        ("name", "price", "qty"), [("", 1, 1), ("x", -1, 1), ("x", 1, 0)]
    )
    def test_invalid_items_rejected(self, name: str, price: int, qty: int) -> None:
        with pytest.raises(ValueError):
            CartItem(name=name, unit_price_paise=price, quantity=qty)

    def test_negative_budget_rejected(self) -> None:
        with pytest.raises(ValueError, match="budget_paise"):
            PurchaseIntent(description="x", budget_paise=-1, merchant_id="m")

    def test_cart_item_is_frozen(self) -> None:
        item = CartItem(name="x", unit_price_paise=1, quantity=1)
        with pytest.raises((AttributeError, TypeError)):
            item.unit_price_paise = 999  # type: ignore[misc]

    def test_proposal_to_dict_is_serialisable(self, key: None) -> None:
        proposal = BuyingAgent(
            chain_with(Scripted(ok(cart_json(("apple", 100, 2)))))
        ).propose(intent())
        payload = json.loads(json.dumps(proposal.to_dict()))
        assert payload["total_paise"] == 200
        assert payload["items"][0]["line_total_paise"] == 200
