"""Policy as a versioned document, not scattered conditionals.

A policy declares which obligations must be evaluated, what parameters each
predicate uses, and which authority stands behind it. That declaration is what
drives the coverage invariant in ADR-0003: the kernel demands a result for every
declared obligation and materialises ``INDETERMINATE`` for any that is missing.

Three properties this buys, none of which a hard-coded rule set gives you:

* **Versioned.** ``policy_version`` is stamped on every verdict, so a decision
  can be reproduced against the exact rules in force when it was made.
* **Cited.** Every regulatory obligation carries its provision (ADR-0006). The
  loader refuses a regulatory rule with no citation, so a policy file cannot
  smuggle in an unsourced legal claim.
* **Swappable.** A different jurisdiction is a different file, not a different
  build. The kernel does not change.

Parameters are deliberately *not* free-form: a predicate declares the keys it
requires and the loader fails on anything unknown, so a typo in a threshold name
is a load error rather than a silently skipped check.
"""

from __future__ import annotations

import importlib.resources
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

import yaml

from pramana.kernel.verdict import Citation, ObligationSource

HANDOFF_KEY: Final = "defers_to"
"""Param under which an obligation declares that another one holds a case."""

RESOLVED_HANDOFF_KEY: Final = "deferred_categories"
"""Where :class:`Policy` writes the resolved handoff for the predicate to read.

Never written by hand. A policy file that sets it is refused, because a
hand-written copy is exactly the drift the resolution exists to prevent.
"""


class PolicyError(Exception):
    """The policy document is invalid. Never raised at decision time."""


@dataclass(frozen=True, slots=True)
class ObligationSpec:
    """One declared obligation and the parameters its predicate needs."""

    id: str
    source: ObligationSource
    description: str
    params: Mapping[str, Any] = field(default_factory=dict)
    citation: Citation | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.id:
            raise PolicyError("obligation id must be non-empty")
        if self.source is ObligationSource.REGULATORY and self.citation is None:
            raise PolicyError(
                f"obligation {self.id!r} is REGULATORY but declares no citation. "
                "A policy cannot assert a legal requirement without naming it."
            )
        if self.source is ObligationSource.RISK:
            raise PolicyError(
                f"obligation {self.id!r} declares source RISK. Advisory signals "
                "must never be declared: declaring demands a result, and an "
                "advisory signal is one we proceed without. See ADR-0005."
            )

    def param(self, key: str, default: Any = None) -> Any:
        return self.params.get(key, default)

    def require(self, key: str) -> Any:
        """Fetch a parameter a predicate cannot run without."""
        if key not in self.params:
            raise PolicyError(
                f"obligation {self.id!r} is missing required parameter {key!r}"
            )
        return self.params[key]


@dataclass(frozen=True, slots=True)
class Policy:
    """A complete, versioned policy document."""

    version: str
    description: str
    obligations: tuple[ObligationSpec, ...]
    jurisdiction: str = ""

    def __post_init__(self) -> None:
        if not self.version:
            raise PolicyError("policy version is required")
        ids = [o.id for o in self.obligations]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise PolicyError(f"duplicate obligation ids: {sorted(duplicates)}")
        if not self.enabled:
            raise PolicyError(
                f"policy {self.version!r} enables no obligations; it could only "
                "ever produce an unchecked ALLOW"
            )
        object.__setattr__(self, "obligations", self._resolve_handoffs())

    def _resolve_handoffs(self) -> tuple[ObligationSpec, ...]:
        """Bind every declared handoff to its receiver, or refuse to load.

        One obligation may step aside for another: ``rbi.afa_threshold`` hands
        the enhanced-ceiling categories to ``rbi.category_ceiling`` rather than
        applying the standard ceiling to them. That is a *transfer of
        responsibility*, and it has the failure mode every transfer has --
        nobody receives it.

        No verdict-level invariant can catch that. Both obligations report a
        result, so coverage is satisfied; both results are ``NOT_APPLICABLE``,
        so nothing blocks; and each predicate is individually correct, because
        each was told the other one had it. The rule simply goes unenforced.
        It is the same defect as an obligation with no result, one layer up:
        **a handoff with no receiver is absence wearing a delegation.**

        So it is caught here, at load, where it is still visible -- and the
        receiving list is *read from the receiver* rather than copied, so the
        two cannot drift apart in the first place. A policy is loaded once at
        startup, so refusing to load is the cheapest possible failure.
        """
        resolved: list[ObligationSpec] = []
        for spec in self.obligations:
            raw = spec.param(HANDOFF_KEY)
            if raw is None:
                if RESOLVED_HANDOFF_KEY in spec.params:
                    raise PolicyError(
                        f"obligation {spec.id!r} sets {RESOLVED_HANDOFF_KEY!r} "
                        f"but declares no {HANDOFF_KEY!r}. That key is derived "
                        f"from the receiving obligation and is overwritten on "
                        f"every load, so a hand-written value does nothing at "
                        f"all -- which is worse than being wrong."
                    )
                resolved.append(spec)
                continue
            if not spec.enabled:
                # A disabled obligation defers nothing; it is not evaluated.
                resolved.append(spec)
                continue
            # Always overwritten, never merged: the receiver is the only source
            # of this list, so no copy of it can survive to drift.
            resolved.append(
                replace(spec, params={
                    **spec.params,
                    RESOLVED_HANDOFF_KEY: self._receive(spec, raw),
                })
            )
        return tuple(resolved)

    def _receive(self, spec: ObligationSpec, raw: Any) -> tuple[str, ...]:
        """Validate one handoff and return the receiver's list of cases."""
        if not isinstance(raw, dict):
            raise PolicyError(
                f"obligation {spec.id!r}: {HANDOFF_KEY!r} must be a mapping"
            )
        unknown = set(raw) - {"obligation", "when_category_in"}
        if unknown:
            raise PolicyError(
                f"obligation {spec.id!r}: unknown {HANDOFF_KEY!r} keys "
                f"{sorted(unknown)}"
            )
        receiver_id = str(raw.get("obligation", "")).strip()
        param_name = str(raw.get("when_category_in", "")).strip()
        if not receiver_id or not param_name:
            raise PolicyError(
                f"obligation {spec.id!r}: {HANDOFF_KEY!r} requires both "
                f"'obligation' and 'when_category_in'"
            )

        receiver = self.spec(receiver_id)
        if receiver is None:
            raise PolicyError(
                f"obligation {spec.id!r} defers to {receiver_id!r}, which this "
                f"policy does not declare. A handoff with no receiver leaves the "
                f"rule unenforced by both."
            )
        if not receiver.enabled:
            raise PolicyError(
                f"obligation {spec.id!r} defers to {receiver_id!r}, which is "
                f"disabled. Disabling the receiver does not disable the rule -- "
                f"it silently drops it. Remove the handoff too, deliberately."
            )
        cases = receiver.param(param_name)
        if not isinstance(cases, list) or not cases:
            raise PolicyError(
                f"obligation {spec.id!r} defers to {receiver_id!r}.{param_name}, "
                f"which is not a non-empty list. There is nothing to receive."
            )
        return tuple(str(c) for c in cases)

    @property
    def enabled(self) -> tuple[ObligationSpec, ...]:
        return tuple(o for o in self.obligations if o.enabled)

    @property
    def declared_ids(self) -> frozenset[str]:
        """What the kernel must produce a result for. Drives ADR-0003 coverage."""
        return frozenset(o.id for o in self.enabled)

    def spec(self, obligation_id: str) -> ObligationSpec | None:
        for o in self.obligations:
            if o.id == obligation_id:
                return o
        return None

    def by_source(self, source: ObligationSource) -> tuple[ObligationSpec, ...]:
        return tuple(o for o in self.enabled if o.source is source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "description": self.description,
            "jurisdiction": self.jurisdiction,
            "obligations": [
                {
                    "id": o.id,
                    "source": str(o.source),
                    "description": o.description,
                    "params": dict(o.params),
                    "enabled": o.enabled,
                    "citation": o.citation.to_dict() if o.citation else None,
                }
                for o in self.obligations
            ],
        }


def _citation_from(raw: Any, obligation_id: str) -> Citation | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyError(f"obligation {obligation_id!r}: citation must be a mapping")
    unknown = set(raw) - {"authority", "reference", "clause", "effective_from", "url"}
    if unknown:
        raise PolicyError(
            f"obligation {obligation_id!r}: unknown citation keys {sorted(unknown)}"
        )
    try:
        return Citation(
            authority=str(raw.get("authority", "")),
            reference=str(raw.get("reference", "")),
            clause=raw.get("clause"),
            effective_from=raw.get("effective_from"),
            url=raw.get("url"),
        )
    except ValueError as exc:
        raise PolicyError(f"obligation {obligation_id!r}: {exc}") from exc


def _spec_from(raw: Any, index: int) -> ObligationSpec:
    if not isinstance(raw, dict):
        raise PolicyError(
            f"obligation #{index} must be a mapping, got {type(raw).__name__}"
        )
    unknown = set(raw) - {
        "id", "source", "description", "params", "citation", "enabled",
    }
    if unknown:
        raise PolicyError(f"obligation #{index}: unknown keys {sorted(unknown)}")

    obligation_id = str(raw.get("id", "")).strip()
    if not obligation_id:
        raise PolicyError(f"obligation #{index}: id is required")

    raw_source = str(raw.get("source", "")).strip()
    try:
        source = ObligationSource(raw_source)
    except ValueError as exc:
        valid = ", ".join(str(s) for s in ObligationSource)
        raise PolicyError(
            f"obligation {obligation_id!r}: unknown source {raw_source!r}. "
            f"Valid: {valid}"
        ) from exc

    params = raw.get("params") or {}
    if not isinstance(params, dict):
        raise PolicyError(f"obligation {obligation_id!r}: params must be a mapping")

    return ObligationSpec(
        id=obligation_id,
        source=source,
        description=str(raw.get("description", "")),
        params=dict(params),
        citation=_citation_from(raw.get("citation"), obligation_id),
        enabled=bool(raw.get("enabled", True)),
    )


def load_policy(source: str | Path) -> Policy:
    """Load a policy from a YAML file path or a YAML string.

    Raises :class:`PolicyError` on anything malformed. A policy is loaded once
    at startup, never at decision time, so failing loudly here is correct.
    """
    text = (
        Path(source).read_text(encoding="utf-8")
        if isinstance(source, Path) or (
            isinstance(source, str) and source.endswith((".yaml", ".yml"))
        )
        else str(source)
    )

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError("policy document must be a mapping at the top level")

    unknown = set(raw) - {"version", "description", "jurisdiction", "obligations"}
    if unknown:
        raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")

    raw_obligations = raw.get("obligations")
    if not isinstance(raw_obligations, list) or not raw_obligations:
        raise PolicyError("policy must declare a non-empty 'obligations' list")

    return Policy(
        version=str(raw.get("version", "")).strip(),
        description=str(raw.get("description", "")),
        jurisdiction=str(raw.get("jurisdiction", "")),
        obligations=tuple(
            _spec_from(o, i) for i, o in enumerate(raw_obligations)
        ),
    )


BUILTIN_POLICIES: Final = ("rbi-in",)
"""Policies shipped inside the package."""


def builtin_policy(name: str = "rbi-in") -> Policy:
    """Load a policy that ships with PRAMANA, from anywhere.

    Resolved through ``importlib.resources`` rather than a path relative to the
    working directory. The earlier ``Path("policies/rbi-in.yaml")`` worked only
    when the process happened to be started from the repository root: running
    ``pytest`` from ``tests/`` produced 34 failures, and ``pramana bench`` from
    any other directory could not find the file at all.
    """
    if name not in BUILTIN_POLICIES:
        raise PolicyError(
            f"unknown builtin policy {name!r}; available: {list(BUILTIN_POLICIES)}"
        )
    resource = importlib.resources.files("pramana") / "policies" / f"{name}.yaml"
    try:
        return load_policy(resource.read_text(encoding="utf-8"))
    except (OSError, FileNotFoundError) as exc:
        raise PolicyError(
            f"builtin policy {name!r} is missing from the installed package. "
            "This usually means package-data was not included in the build."
        ) from exc
