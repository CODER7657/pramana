# Contributing

PRAMANA is a verification gate on the money path, so changes are held to one rule above
all: **a verifier must be able to tell "checked and passed" apart from "never checked".**

## Ground rules

- No model on the money path. Verdicts come from deterministic predicates only.
- A declared obligation with no result is `INDETERMINATE`, which rejects. Never make
  absence look like compliance.
- Every threshold in `pramana/policies/` cites its source; regenerate the policy
  reference (`python scripts/gen_policy_reference.py`) when a policy changes.
- One issue, one branch, one pull request, with tests including failure paths. The
  README's test count is asserted by a test; update it with your tests.
- No secrets or real personal data.

## Set up and test

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && mypy pramana bench
pytest -q
```

Changes to the evaluator (`pramana/kernel/gate.py`, `verdict.py`, `verify/`) also run
the mutation gate (`.github/workflows/mutation.yml`).

## Pull requests

Say what changed and why, and paste the real test output. Security issues: see
[SECURITY.md](SECURITY.md).
