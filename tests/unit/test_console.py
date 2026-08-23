"""Console rendering of untrusted text.

Regression suite for a demo-fatal bug found on 2026-08-23: a live model returned
a narrow no-break space (U+202F) inside an explanation, the cp1252 console could
not encode it, and the whole command died with UnicodeEncodeError mid-output.

Model output is not ours to constrain, so this has to hold for arbitrary input.

Every non-ASCII character below is written as an escape sequence on purpose.
This file must not itself contain literal control or invisible characters.
"""

from __future__ import annotations

import pytest

from pramana.console import console_safe

NNBSP = " "  # narrow no-break space -- the character that crashed the demo


class TestTheBugThatCrashedTheDemo:
    def test_narrow_no_break_space_is_transliterated(self) -> None:
        """U+202F, exactly as emitted by gpt-oss-120b in '67 %'."""
        assert console_safe("67" + NNBSP + "%") == "67 %"

    def test_result_encodes_on_a_cp1252_console(self) -> None:
        raw = "67" + NNBSP + "% — done “ok”"
        rendered = console_safe(raw)
        assert rendered.encode("cp1252")
        assert rendered.encode("ascii")

    def test_the_original_crash_no_longer_raises(self) -> None:
        """Before the fix this raised UnicodeEncodeError on encode."""
        console_safe("Only 67" + NNBSP + "% of checks ran.").encode("cp1252")


class TestTransliteration:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("‘quoted’", "'quoted'"),
            ("“quoted”", '"quoted"'),
            ("a — b", "a -- b"),
            ("a – b", "a - b"),
            ("wait…", "wait..."),
            ("₹5,000", "INR 5,000"),
            ("a → b", "a -> b"),
            ("x ≤ y", "x <= y"),
            ("• item", "* item"),
            ("a b", "a b"),
            ("a" + NNBSP + "b", "a b"),
        ],
    )
    def test_common_model_punctuation(self, raw: str, expected: str) -> None:
        assert console_safe(raw) == expected

    def test_accents_decompose_to_base_letters(self) -> None:
        """'cafe' is more useful than 'caf?'."""
        assert console_safe("café naïve") == "cafe naive"

    def test_ascii_passes_through_unchanged(self) -> None:
        text = "Payment rejected under policy p@1 (67%)."
        assert console_safe(text) == text

    def test_unrepresentable_falls_back_rather_than_raising(self) -> None:
        rendered = console_safe("emoji \U0001f600 and 中文")
        assert rendered.encode("ascii")
        assert "emoji" in rendered

    def test_empty_string(self) -> None:
        assert console_safe("") == ""

    @pytest.mark.parametrize(
        "raw",
        [
            NNBSP + " —“₹\U0001f600",
            "mixed é text → here",
            "\x00control\x1b[31m",
            "a" * 1000 + NNBSP,
            "中文 only",
        ],
    )
    def test_output_is_always_ascii(self, raw: str) -> None:
        assert console_safe(raw).isascii()


class TestIdempotence:
    @pytest.mark.parametrize(
        "raw",
        [
            "67" + NNBSP + "%",
            "“hi”",
            "café",
            "plain text",
            "₹1,000 — done",
        ],
    )
    def test_applying_twice_changes_nothing(self, raw: str) -> None:
        once = console_safe(raw)
        assert console_safe(once) == once
