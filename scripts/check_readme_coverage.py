#!/usr/bin/env python
"""Fail if the README's coverage badge disagrees with measured coverage.

Run **after** ``pytest --cov``, which writes the ``.coverage`` data file this
reads. In CI that is the step immediately following the test run.

Why this is a script and not a test
-----------------------------------

The test count is asserted by a test because a test can re-collect the suite in
a subprocess and get a true answer. Coverage cannot work that way: a test that
inspects coverage *while the run producing it is still in progress* either sees
incomplete data or the stale file from a previous run, and a gate that reports
last run's number is worse than no gate -- it is a gate that lies.

So the value check runs after the session ends, where the number is real.
``tests/unit/test_cli.py`` separately asserts the README states exactly *one*
coverage number, which needs no data and catches the failure mode that actually
happened to the test count: three different figures in one document.

This exists because coverage went 95.1% -> 94.3% when the AP2 adapter, the
corpus and the counterfactual landed, and both the badge and the POSTMORTEM
table went on saying 95% -- in a repository whose pitch is that its numbers are
checkable.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BADGE = re.compile(r"coverage-(\d{1,3})%25")
POSTMORTEM_ROW = re.compile(r"\|\s*Statement coverage\s*\|\s*\*\*(\d{1,3})%\*\*\s*\|")


def measured() -> int:
    """The integer coverage percentage, from the data pytest --cov just wrote."""
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "report", "--format=total"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if result.returncode != 0:
        raise SystemExit(
            "could not read coverage data. Run `pytest --cov=pramana --cov=bench` "
            f"first.\n{result.stderr.strip()}"
        )
    return int(result.stdout.strip())


def claimed(path: Path, pattern: re.Pattern[str]) -> list[int]:
    return [int(m) for m in pattern.findall(path.read_text(encoding="utf-8"))]


def main() -> int:
    actual = measured()
    problems: list[str] = []

    for name, pattern in (
        ("README.md", BADGE),
        ("POSTMORTEM.md", POSTMORTEM_ROW),
    ):
        stated = claimed(ROOT / name, pattern)
        if not stated:
            problems.append(f"{name} states no coverage number")
        elif set(stated) != {actual}:
            problems.append(
                f"{name} claims {sorted(set(stated))}% coverage; measured {actual}%"
            )

    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    print(f"coverage badge matches measured coverage: {actual}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
