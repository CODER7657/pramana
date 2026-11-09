"""Generate the policy reference from the policy-as-code definition.

    python scripts/gen_policy_reference.py          # write both files
    python scripts/gen_policy_reference.py --check  # exit 1 if either is stale

Reads ``pramana/policies/rbi-in.yaml`` through the same loader the gate uses, finds the
code that evaluates each obligation (``rbi.PREDICATES`` for regulatory rules, the AP2
adapters for the rest), and writes:

* ``public/policy.html``: the page linked from the playground (served by Vercel's CDN);
* ``docs/policy-reference.md``: the same content for GitHub.

``tests/unit/test_policy_reference.py`` fails if either file drifts from the policy.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pramana.kernel.verdict import Citation  # noqa: E402
from pramana.kernel.verify import rbi  # noqa: E402
from pramana.kernel.verify.policy import ObligationSpec, Policy, builtin_policy  # noqa: E402

POLICY_NAME = "rbi-in"
HTML_OUT = ROOT / "public" / "policy.html"
MD_OUT = ROOT / "docs" / "policy-reference.md"
REPO = "https://github.com/CODER7657/pramana/blob/main"
RBI_SOURCE = "pramana/kernel/verify/rbi.py"
ADAPTERS = ("pramana/adapters/ap2.py", "pramana/adapters/ap2_chain.py")

GROUPS = (
    ("protocol", "Protocol integrity", "The AP2 delegation chain itself."),
    ("mandate", "Mandate conformance", "Limits the user chose and signed."),
    (
        "merchant",
        "Merchant rules",
        "Rules that bind even when the mandate allows more.",
    ),
    ("regulatory", "RBI e-mandate framework", "Rules no mandate can waive."),
)


def evaluated_by(spec_id: str) -> tuple[str, str]:
    """(label, repo-relative path#Lline) of the code that produces this obligation."""
    fn = rbi.PREDICATES.get(spec_id)
    if fn is not None:
        # Read the definition from the source text, not by introspection: under mutation
        # testing the registered functions are wrappers that live elsewhere.
        name = fn.__name__
        source = (ROOT / RBI_SOURCE).read_text(encoding="utf-8").splitlines()
        line = next(n for n, t in enumerate(source, 1) if t.startswith(f"def {name}("))
        return f"rbi.{name}()", f"{RBI_SOURCE}#L{line}"
    needle = f'"{spec_id}"'
    for rel in ADAPTERS:
        lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()
        for n, text in enumerate(lines, 1):
            if needle not in text:
                continue
            # `NAME: Final = "id"` names the id: link the first line that builds the
            # Obligation with that name, not the declaration.
            decl = r"\s*([A-Z_][A-Z0-9_]*)\s*(?::[^=]+)?=\s*" + re.escape(needle)
            const = re.match(decl, text)
            line = n
            if const:
                use = re.compile(r"(_ob\(|id=)\s*" + const.group(1) + r"\b")
                line = next((m for m, t in enumerate(lines, 1) if use.search(t)), n)
            return Path(rel).stem + " adapter", f"{rel}#L{line}"
    raise LookupError(f"no code produces {spec_id!r}; it would always be INDETERMINATE")


def cite(c: Citation) -> str:
    ref = f"{c.authority}, {c.reference}"
    if c.clause:
        ref += f", {c.clause}"
    if c.effective_from:
        ref += f" (effective {c.effective_from})"
    return ref


def money(value: object, key: str) -> str:
    if key.endswith("_paise") and isinstance(value, int):
        return f"{value:,} paise (INR {value // 100:,})"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def grouped(policy: Policy) -> Iterator[tuple[str, str, list[ObligationSpec]]]:
    for key, title, lede in GROUPS:
        specs = [s for s in policy.obligations if str(s.source) == key]
        if specs:
            yield title, lede, specs
    known = {g[0] for g in GROUPS}
    rest = [s for s in policy.obligations if str(s.source) not in known]
    if rest:
        yield "Other", "", rest


def markdown(policy: Policy) -> str:
    out = [
        f"# Policy reference: `{policy.version}`",
        "",
        "Generated from [`pramana/policies/rbi-in.yaml`]"
        "(../pramana/policies/rbi-in.yaml) by `scripts/gen_policy_reference.py`;",
        "do not edit by hand. Every obligation below is evaluated on every payment.",
        "One with no result is `INDETERMINATE`, which rejects.",
        "",
        f"> {policy.description}",
        "",
    ]
    for title, lede, specs in grouped(policy):
        out += [f"## {title}", "", lede, ""] if lede else [f"## {title}", ""]
        for s in specs:
            label, where = evaluated_by(s.id)
            out += [f"### `{s.id}`", "", " ".join(s.description.split()), ""]
            if s.params:
                out += [f"- **{k}:** {money(v, k)}" for k, v in s.params.items()]
            out.append(f"- **Evaluated by:** [`{label}`](../{where})")
            if not s.enabled:
                out.append("- **Disabled** in this policy version.")
            if s.citation:
                c = s.citation
                ref = cite(c)
                out.append(f"- **Source:** {ref}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


CSS = (Path(__file__).with_name("policy_reference.css")).read_text(encoding="utf-8")


def page(policy: Policy) -> str:
    e = html.escape
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>PRAMANA policy reference: {e(policy.version)}</title>",
        '<meta name="description" content="Every obligation in the '
        f"{e(policy.version)} policy, its parameters, the code that evaluates it, "
        'and its source.">',
        f"<style>{CSS.strip()}</style></head><body>",
        '<header><div class="row"><strong>PRAMANA</strong>',
        '<nav aria-label="Links"><a href="/">Playground</a> · '
        '<a href="/v1/policy">Policy JSON</a> · '
        '<a href="https://github.com/CODER7657/pramana">Source</a></nav></div></header>',
        "<main>",
        f"<h1>Policy reference: <code>{e(policy.version)}</code></h1>",
        f'<p class="lede">{e(" ".join(policy.description.split()))}</p>',
        '<p class="note">Generated from <a href="'
        f'{REPO}/pramana/policies/rbi-in.yaml">'
        "<code>pramana/policies/rbi-in.yaml</code></a>. "
        "Every obligation is evaluated on every payment; one with no result is "
        "<strong>INDETERMINATE</strong>, which rejects.</p>",
    ]
    for title, lede, specs in grouped(policy):
        parts.append(f"<h2>{e(title)}</h2>")
        if lede:
            parts.append(f'<p class="lede">{e(lede)}</p>')
        for s in specs:
            label, where = evaluated_by(s.id)
            rows = [(k, money(v, k)) for k, v in s.params.items()]
            parts.append(f'<article id="{e(s.id)}"><div class="id">{e(s.id)}</div>')
            parts.append(f"<p>{e(' '.join(s.description.split()))}</p><dl>")
            for k, v in rows:
                parts.append(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>")
            link = f'<a href="{REPO}/{e(where)}"><code>{e(label)}</code></a>'
            parts.append(f"<dt>Evaluated by</dt><dd>{link}</dd>")
            if not s.enabled:
                parts.append("<dt>Status</dt><dd>Disabled in this policy version</dd>")
            if s.citation:
                c = s.citation
                ref = cite(c)
                parts.append(f"<dt>Source</dt><dd>{e(ref)}</dd>")
            parts.append("</dl></article>")
    parts.append("</main></body></html>")
    return "\n".join(parts) + "\n"


def render() -> dict[Path, str]:
    policy = builtin_policy(POLICY_NAME)
    return {HTML_OUT: page(policy), MD_OUT: markdown(policy)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if a file is stale")
    args = ap.parse_args(argv)
    stale = []
    for path, text in render().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != text:
            stale.append(path)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
    rel = [p.relative_to(ROOT).as_posix() for p in stale]
    if args.check:
        if stale:
            print("stale (run scripts/gen_policy_reference.py):", ", ".join(rel))
            return 1
        print("policy reference is current")
        return 0
    print("wrote:", ", ".join(rel) if rel else "nothing (already current)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
