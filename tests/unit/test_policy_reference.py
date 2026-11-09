"""The generated policy reference matches the policy-as-code definition."""

import importlib.util
import sys
from pathlib import Path

import pytest

from pramana.kernel.verify.policy import builtin_policy

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.unit


def _gen():
    spec = importlib.util.spec_from_file_location(
        "gen_policy_reference", ROOT / "scripts" / "gen_policy_reference.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_committed_reference_is_current():
    assert _gen().main(["--check"]) == 0, "run: python scripts/gen_policy_reference.py"


def test_every_obligation_is_documented_with_the_code_that_evaluates_it():
    gen = _gen()
    page = gen.HTML_OUT.read_text(encoding="utf-8")
    for spec in builtin_policy("rbi-in").obligations:
        assert f'id="{spec.id}"' in page
        _label, where = gen.evaluated_by(spec.id)
        path, line = where.split("#L")
        source = (ROOT / path).read_text(encoding="utf-8").splitlines()
        evaluating = source[int(line) - 1]
        builds = spec.id in evaluating or "_ob(" in evaluating or "def " in evaluating
        assert builds, (spec.id, where)


def test_an_obligation_no_code_produces_is_refused():
    with pytest.raises(LookupError, match="always be INDETERMINATE"):
        _gen().evaluated_by("rbi.not_a_rule")


def test_paise_are_shown_with_rupees():
    assert _gen().money(1_500_000, "ceiling_paise") == "1,500,000 paise (INR 15,000)"
