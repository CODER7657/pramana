"""The static playground served at ``/`` on Vercel (``public/index.html``).

On Vercel the file is served statically, so the gateway app has no ``/`` route.
The test therefore serves the same file through a ``TestClient`` and checks the
properties that matter: the controls exist, the verdict region is announced, and
nothing is loaded from or leaks to other origins beyond the font stylesheet.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

PAGE = Path(__file__).resolve().parents[2] / "public" / "index.html"

# Pictographs, dingbats, arrows-as-emoji, variation selector 16, ZWJ.
EMOJI = re.compile(
    "[\U0001f000-\U0001faff\u2600-\u27bf\u2b00-\u2bff\ufe0f\u200d\u2300-\u23ff]"
)


@pytest.fixture(scope="module")
def html() -> str:
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return PAGE.read_text(encoding="utf-8")

    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    return response.text


def test_has_all_six_scenarios_in_the_script(html: str) -> None:
    # Scenarios are rendered from this array as buttons with aria-pressed.
    assert len(re.findall(r"\{ t: '", html)) == 6
    assert "setAttribute('aria-pressed'" in html
    assert 'id="cases"' in html


def test_has_evaluate_and_reset_buttons(html: str) -> None:
    assert re.search(r'<button[^>]*id="send"[^>]*>Evaluate</button>', html)
    assert re.search(r'<button[^>]*id="reset"[^>]*>', html)


def test_verdict_region_is_a_polite_live_region(html: str) -> None:
    assert re.search(r'id="result"[^>]*aria-live="polite"', html)


def test_posts_to_evaluate_endpoint_and_reads_headers(html: str) -> None:
    assert "fetch('/v1/evaluate'" in html
    assert "x-pramana-elapsed-ms" in html
    assert "x-pramana-policy-version" in html


def test_no_external_script_and_no_inline_handlers(html: str) -> None:
    srcs = re.findall(r"<script[^>]*\ssrc=[\"']([^\"']+)", html, flags=re.I)
    assert all(not re.match(r"(https?:)?//", s) for s in srcs), srcs
    assert not re.search(r"\son[a-z]+\s*=", html, flags=re.I)


def test_only_font_hosts_are_external(html: str) -> None:
    hosts = set(re.findall(r"(?:href|src)=\"https://([^/\"]+)", html))
    allowed = {
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "github.com",
        "pavanpatel.vercel.app",
    }
    assert hosts <= allowed, hosts - allowed


def test_no_emoji_characters(html: str) -> None:
    assert EMOJI.findall(html) == []


def test_design_tokens_present(html: str) -> None:
    for token in ("--paper:#EDEAE3", "--ink:#1A1A1A", "--reject:#E0201B"):
        assert token in html.replace(": ", ":")


def test_buttons_meet_minimum_touch_height(html: str) -> None:
    assert re.search(r"\.btn\s*\{[^}]*min-height:\s*44px", html)
