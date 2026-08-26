"""The pre-registered set, and the protocol that makes it worth anything.

The cases were sealed in commit 9d0994a with no runner. These tests guard the
two things that could quietly destroy the value of that: an expectation being
edited after the fact, and a disagreement being hidden rather than reported.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from bench.prereg import prereg_cases
from bench.prereg_run import render, run_prereg, summary

OUTCOMES = run_prereg()
SUMMARY = summary(OUTCOMES)


class TestTheSetItself:
    def test_every_case_cites_a_provision_and_a_reason(self) -> None:
        """A case that cannot say which rule decides it is not derived from one."""
        for pre in prereg_cases():
            assert pre.provision.strip(), pre.case.id
            assert pre.reasoning.strip(), pre.case.id

    def test_case_ids_are_unique(self) -> None:
        ids = [p.case.id for p in prereg_cases()]
        assert len(ids) == len(set(ids))

    def test_the_set_tests_both_directions(self) -> None:
        """A set that only expects refusals would be trivially satisfiable."""
        cases = prereg_cases()
        assert sum(1 for c in cases if c.should_allow) >= 5
        assert sum(1 for c in cases if not c.should_allow) >= 5

    def test_it_covers_every_provision_the_policy_claims_to_enforce(self) -> None:
        provisions = {p.provision for p in prereg_cases()}
        assert len(provisions) >= 5

    def test_it_includes_boundary_cases(self) -> None:
        """Off-by-one on a money threshold is real revenue or a real breach."""
        ids = {p.case.id for p in prereg_cases()}
        assert "pr-exactly-at-ceiling-no-afa" in ids
        assert "pr-one-rupee-over-ceiling-no-afa" in ids
        assert "pr-notice-exactly-24h" in ids
        assert "pr-insurance-exactly-1lakh-no-afa" in ids


class TestTheResult:
    def test_the_gate_agrees_with_the_regulation_on_every_sealed_case(self) -> None:
        """The regression gate this set becomes after it is run once.

        If this goes red, the gate's behaviour drifted away from a reading of
        the regulation that was fixed before the code was consulted. That is a
        finding either way and it should stop a merge.
        """
        assert SUMMARY["disagreed"] == 0, SUMMARY["disagreements"]

    def test_every_case_is_accounted_for(self) -> None:
        assert SUMMARY["tp"] + SUMMARY["fp"] + SUMMARY["fn"] + SUMMARY["tn"] == len(
            OUTCOMES
        )
        assert SUMMARY["cases"] == len(prereg_cases())

    def test_no_expectation_was_edited_after_sealing(self) -> None:
        """Git is the evidence, so the test asks git.

        `bench/prereg.py` must not have been modified since the commit that
        sealed it. If it has, the pre-registration claim is void and this test
        says so rather than letting the README keep making it.
        """
        git = shutil.which("git")
        if git is None:
            return
        # S603: the executable is an absolute path from shutil.which and
        # every argument is a literal in this file. Nothing is caller input.
        log = subprocess.run(  # noqa: S603
            [git, "log", "--oneline", "--", "bench/prereg.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        if log.returncode != 0:  # not a git checkout (sdist, CI artifact)
            return
        commits = [line for line in log.stdout.splitlines() if line.strip()]
        assert len(commits) == 1, (
            "bench/prereg.py has been modified since it was sealed; the "
            f"pre-registration claim is no longer true:\n{log.stdout}"
        )


class TestTheReport:
    def test_it_states_what_the_method_does_not_establish(self) -> None:
        text = render(OUTCOMES)
        assert "pre-registration, not blinding" in text
        assert "different author or production" in text
        assert "not a substitute" in text

    def test_it_names_the_sealing_commit(self) -> None:
        assert "9d0994a" in render(OUTCOMES)

    def test_a_disagreement_would_be_printed_not_swallowed(self) -> None:
        """Verified by construction: the renderer's disagreement branch."""
        text = render(OUTCOMES)
        assert ("DISAGREEMENTS" in text) is (SUMMARY["disagreed"] > 0)

    def test_the_cli_exits_non_zero_on_disagreement(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "pramana.cli", "prereg"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == (0 if SUMMARY["disagreed"] == 0 else 1)
        assert "PRE-REGISTERED TEST SET" in result.stdout
