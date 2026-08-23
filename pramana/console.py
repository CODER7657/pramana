"""Console output that cannot crash on untrusted text.

A language model emits whatever it likes. On 2026-08-23 one returned a narrow
no-break space (U+202F) inside an explanation; the Windows cp1252 console could
not encode it and the entire ``print`` raised ``UnicodeEncodeError``, killing
the command mid-output.

That is a demo-fatal class of bug, and it is not fixable by being careful with
our own strings -- model output is not ours. It has to be handled at the render
boundary.

Two layers, because either alone is insufficient:

1. :func:`configure_stdout` switches the streams to UTF-8 with
   ``errors="replace"``, so nothing can raise regardless of what reaches it.
2. :func:`console_safe` transliterates the typographic characters models
   actually emit -- smart quotes, dashes, ellipses, the rupee sign, exotic
   spaces -- into ASCII that reads correctly on any terminal. Replacement
   characters are a last resort, not the normal path.

Layer 1 stops the crash. Layer 2 stops the mojibake.
"""

from __future__ import annotations

import contextlib
import sys
import unicodedata
from typing import Final

_TRANSLITERATIONS: Final[dict[int, str]] = {
    0x00A0: " ",  # no-break space
    0x2002: " ",  # en space
    0x2003: " ",  # em space
    0x2009: " ",  # thin space
    0x202F: " ",  # narrow no-break space -- the one that crashed the demo
    0x2007: " ",  # figure space
    0x2010: "-",  # hyphen
    0x2011: "-",  # non-breaking hyphen
    0x2012: "-",  # figure dash
    0x2013: "-",  # en dash
    0x2014: "--",  # em dash
    0x2015: "--",  # horizontal bar
    0x2018: "'",  # left single quote
    0x2019: "'",  # right single quote
    0x201A: "'",
    0x201B: "'",
    0x201C: '"',  # left double quote
    0x201D: '"',  # right double quote
    0x201E: '"',
    0x2026: "...",  # ellipsis
    0x2032: "'",  # prime
    0x2033: '"',  # double prime
    0x20B9: "INR ",  # rupee sign
    0x20AC: "EUR ",
    0x00A3: "GBP ",
    0x00A5: "JPY ",
    0x2260: "!=",
    0x2264: "<=",
    0x2265: ">=",
    0x00D7: "x",
    0x2192: "->",
    0x2190: "<-",
    0x2022: "*",  # bullet
    0x00B7: "*",  # middle dot
    0x2713: "ok",  # check mark
    0x2717: "x",
}


def console_safe(text: str) -> str:
    """Render arbitrary text as ASCII that reads correctly on any terminal.

    Transliterates the punctuation models actually emit, then decomposes
    remaining accented characters to their base letters, and only then falls
    back to dropping what is left. A stray replacement character in a dispute
    pack is better than a crash, but neither should be the common case.
    """
    if text.isascii():
        return text

    translated = text.translate(_TRANSLITERATIONS)
    if translated.isascii():
        return translated

    # Decompose accents: "café" -> "cafe" rather than "caf?".
    decomposed = unicodedata.normalize("NFKD", translated)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    if stripped.isascii():
        return stripped

    return stripped.encode("ascii", errors="replace").decode("ascii")


def configure_stdout() -> None:
    """Make the streams unable to raise on encoding.

    ``errors="replace"`` is deliberate. A command that prints a ``?`` is
    recoverable; one that raises ``UnicodeEncodeError`` halfway through its
    output is not.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")


def safe_print(*parts: object) -> None:
    """``print`` that transliterates every argument first."""
    print(*(console_safe(str(p)) for p in parts))
