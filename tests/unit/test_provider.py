"""Provider chain: failover, retry, caching, and offline behaviour.

Every test runs with no network and no API key. The transport is injected, so
the retry/backoff/failover logic is exercised directly rather than mocked at
the HTTP library level.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pramana.ai.provider import (
    AllProvidersFailedError,
    HttpResult,
    LLMResponse,
    MissingCredentialError,
    Mode,
    NetworkDisabledError,
    PromptKey,
    ProviderChain,
    ProviderConfig,
    ProviderUnavailableError,
    ResponseCache,
    build_chain,
)

P1 = ProviderConfig(
    name="p1", base_url="https://p1.test/v1", model="m1", api_key_env="P1_KEY"
)
P2 = ProviderConfig(
    name="p2", base_url="https://p2.test/v1", model="m2", api_key_env="P2_KEY"
)


def ok_body(text: str = "hello", model: str = "m1") -> dict[str, Any]:
    return {
        "model": model,
        "choices": [{"message": {"role": "assistant", "content": text}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }


class RecordingTransport:
    """Returns a scripted sequence of results and records every call."""

    def __init__(self, *results: HttpResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def __call__(
        self, url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float
    ) -> HttpResult:
        self.calls.append((url, headers, payload))
        if not self.results:
            raise AssertionError("transport called more times than scripted")
        return self.results.pop(0)


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("P1_KEY", "test-key-1")
    monkeypatch.setenv("P2_KEY", "test-key-2")


def chain(transport: Any, **kw: Any) -> ProviderChain:
    kw.setdefault("providers", (P1, P2))
    kw.setdefault("sleep", lambda _s: None)  # no real backoff in tests
    return ProviderChain(transport=transport, **kw)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSuccess:
    def test_first_provider_answers(self, keys: None) -> None:
        t = RecordingTransport(HttpResult(200, ok_body("the cap was withheld")))
        r = chain(t).complete("why?")
        assert r.text == "the cap was withheld"
        assert r.provider == "p1"
        assert r.cached is False
        assert r.prompt_tokens == 11
        assert len(t.calls) == 1

    def test_request_shape_is_openai_compatible(self, keys: None) -> None:
        t = RecordingTransport(HttpResult(200, ok_body()))
        chain(t).complete("q", system="s", max_tokens=64, temperature=0.0)
        url, headers, payload = t.calls[0]
        assert url == "https://p1.test/v1/chat/completions"
        assert headers["Authorization"] == "Bearer test-key-1"
        assert payload["messages"] == [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "q"},
        ]
        assert payload["max_tokens"] == 64
        assert payload["temperature"] == 0.0

    def test_system_message_omitted_when_empty(self, keys: None) -> None:
        t = RecordingTransport(HttpResult(200, ok_body()))
        chain(t).complete("q")
        assert [m["role"] for m in t.calls[0][2]["messages"]] == ["user"]

    def test_max_tokens_clamped_to_provider_ceiling(self, keys: None) -> None:
        small = ProviderConfig(
            name="small",
            base_url="https://s.test/v1",
            model="m",
            api_key_env="P1_KEY",
            max_tokens=32,
        )
        t = RecordingTransport(HttpResult(200, ok_body()))
        chain(t, providers=(small,)).complete("q", max_tokens=9999)
        assert t.calls[0][2]["max_tokens"] == 32


# ---------------------------------------------------------------------------
# Failover -- the Failure Recovery story
# ---------------------------------------------------------------------------


class TestFailover:
    def test_falls_through_to_second_provider(self, keys: None) -> None:
        t = RecordingTransport(
            HttpResult(401, {}, "invalid api key"),
            HttpResult(200, ok_body("from p2", model="m2")),
        )
        r = chain(t).complete("q")
        assert r.provider == "p2"
        assert len(t.calls) == 2

    def test_rate_limit_retries_then_fails_over(self, keys: None) -> None:
        # p1: 429 three times (initial + 2 retries), then p2 succeeds.
        t = RecordingTransport(
            HttpResult(429, {}, "rate limited"),
            HttpResult(429, {}, "rate limited"),
            HttpResult(429, {}, "rate limited"),
            HttpResult(200, ok_body("from p2")),
        )
        r = chain(t).complete("q")
        assert r.provider == "p2"
        assert len(t.calls) == 4

    def test_retryable_status_recovers_on_second_attempt(self, keys: None) -> None:
        t = RecordingTransport(
            HttpResult(503, {}, "unavailable"),
            HttpResult(200, ok_body("recovered")),
        )
        r = chain(t).complete("q")
        assert r.provider == "p1"
        assert r.text == "recovered"

    def test_backoff_is_exponential(self, keys: None) -> None:
        slept: list[float] = []
        t = RecordingTransport(
            HttpResult(429, {}, "x"),
            HttpResult(429, {}, "x"),
            HttpResult(200, ok_body()),
        )
        c = chain(t, sleep=slept.append, backoff_base_s=0.5)
        c.complete("q")
        assert slept == [0.5, 1.0]

    def test_transport_exception_is_a_provider_failure_not_a_crash(
        self, keys: None
    ) -> None:
        t = RecordingTransport(
            HttpResult(0, {}, "ConnectError: no route to host"),
            HttpResult(0, {}, "ConnectError: no route to host"),
            HttpResult(0, {}, "ConnectError: no route to host"),
            HttpResult(200, ok_body("from p2")),
        )
        assert chain(t).complete("q").provider == "p2"

    def test_all_providers_failed_raises_with_detail(self, keys: None) -> None:
        t = RecordingTransport(
            HttpResult(401, {}, "bad key"),
            HttpResult(401, {}, "bad key"),
        )
        with pytest.raises(AllProvidersFailedError) as exc:
            chain(t).complete("q")
        assert len(exc.value.failures) == 2
        assert "p1" in str(exc.value)
        assert "p2" in str(exc.value)

    def test_missing_credential_skips_provider(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("P1_KEY", raising=False)
        monkeypatch.setenv("P2_KEY", "k")
        t = RecordingTransport(HttpResult(200, ok_body("from p2")))
        r = chain(t).complete("q")
        assert r.provider == "p2"
        assert len(t.calls) == 1, "p1 must not be contacted without a key"

    def test_no_credentials_at_all_fails_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("P1_KEY", raising=False)
        monkeypatch.delenv("P2_KEY", raising=False)
        t = RecordingTransport()
        with pytest.raises(AllProvidersFailedError) as exc:
            chain(t).complete("q")
        assert all(isinstance(f, MissingCredentialError) for f in exc.value.failures)
        assert t.calls == []

    def test_blank_api_key_treated_as_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("P1_KEY", "   ")
        assert P1.api_key() is None

    def test_available_reports_only_credentialed_providers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("P1_KEY", raising=False)
        monkeypatch.setenv("P2_KEY", "k")
        assert [p.name for p in chain(RecordingTransport()).available()] == ["p2"]


# ---------------------------------------------------------------------------
# Malformed responses -- a provider we do not control
# ---------------------------------------------------------------------------


class TestMalformedResponses:
    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"choices": []},
            {"choices": [{}]},
            {"choices": [{"message": {}}]},
            {"choices": "not-a-list"},
        ],
    )
    def test_unparseable_shape_fails_over(
        self, keys: None, body: dict[str, Any]
    ) -> None:
        # max_retries=0: p1 consumes one result, p2 consumes the next.
        t = RecordingTransport(
            HttpResult(200, body),
            HttpResult(200, ok_body("from p2")),
        )
        assert chain(t, max_retries=0).complete("q").provider == "p2"

    @pytest.mark.parametrize("text", ["", "   ", "\n\t"])
    def test_empty_completion_rejected(self, keys: None, text: str) -> None:
        t = RecordingTransport(
            HttpResult(200, ok_body(text)),
            HttpResult(200, ok_body("real answer")),
        )
        r = chain(t, max_retries=0).complete("q")
        assert r.text == "real answer"
        assert r.provider == "p2"

    def test_whitespace_is_stripped(self, keys: None) -> None:
        t = RecordingTransport(HttpResult(200, ok_body("  padded  ")))
        assert chain(t).complete("q").text == "padded"


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class TestCache:
    def test_roundtrip(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        key = PromptKey(system="s", prompt="p", max_tokens=10, temperature=0.0)
        assert cache.get(key) is None
        cache.put(
            key,
            LLMResponse(
                text="answer",
                provider="p1",
                model="m1",
                cached=False,
                latency_ms=12.0,
            ),
        )
        hit = cache.get(key)
        assert hit is not None
        assert hit.text == "answer"
        assert hit.cached is True
        assert hit.provider == "p1", "provenance of the original answer is kept"
        assert len(cache) == 1

    def test_key_digest_is_stable_and_content_sensitive(self) -> None:
        a = PromptKey(system="s", prompt="p", max_tokens=10, temperature=0.0)
        b = PromptKey(system="s", prompt="p", max_tokens=10, temperature=0.0)
        c = PromptKey(system="s", prompt="P", max_tokens=10, temperature=0.0)
        assert a.digest() == b.digest()
        assert a.digest() != c.digest()
        assert len(a.digest()) == 64

    def test_cache_hit_skips_the_network(self, keys: None, tmp_path: Path) -> None:
        t = RecordingTransport(HttpResult(200, ok_body("live answer")))
        c = chain(t, cache=ResponseCache(tmp_path))
        first = c.complete("q")
        assert first.cached is False
        second = c.complete("q")
        assert second.cached is True
        assert second.text == "live answer"
        assert len(t.calls) == 1, "second call must not hit the network"

    def test_refresh_mode_bypasses_read_but_still_writes(
        self, keys: None, tmp_path: Path
    ) -> None:
        cache = ResponseCache(tmp_path)
        t = RecordingTransport(
            HttpResult(200, ok_body("first")),
            HttpResult(200, ok_body("second")),
        )
        c = chain(t, cache=cache, mode=Mode.REFRESH)
        assert c.complete("q").text == "first"
        assert c.complete("q").text == "second"
        assert len(t.calls) == 2
        assert len(cache) == 1

    def test_corrupt_cache_entry_is_ignored(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        key = PromptKey(system="", prompt="p", max_tokens=1, temperature=0.0)
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / f"{key.digest()}.json").write_text("{not json", encoding="utf-8")
        assert cache.get(key) is None

    def test_cache_write_failure_does_not_break_the_caller(
        self, keys: None, tmp_path: Path
    ) -> None:
        # Point the cache at a path that cannot be a directory.
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file", encoding="utf-8")
        t = RecordingTransport(HttpResult(200, ok_body("still works")))
        r = chain(t, cache=ResponseCache(blocker / "sub")).complete("q")
        assert r.text == "still works"


# ---------------------------------------------------------------------------
# Offline -- the demo must survive having no network
# ---------------------------------------------------------------------------


class TestOffline:
    def test_cache_only_serves_from_cache(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        key = PromptKey(system="", prompt="q", max_tokens=512, temperature=0.0)
        cache.put(
            key,
            LLMResponse(
                text="rehearsed", provider="p1", model="m1", cached=False,
                latency_ms=1.0,
            ),
        )
        t = RecordingTransport()  # any call would raise
        r = chain(t, cache=cache, mode=Mode.CACHE_ONLY).complete("q")
        assert r.text == "rehearsed"
        assert r.cached is True
        assert t.calls == []

    def test_cache_only_without_a_hit_raises_rather_than_dialling_out(
        self, tmp_path: Path
    ) -> None:
        t = RecordingTransport()
        with pytest.raises(NetworkDisabledError):
            chain(t, cache=ResponseCache(tmp_path), mode=Mode.CACHE_ONLY).complete("q")
        assert t.calls == []

    def test_cache_only_with_no_cache_configured_raises(self) -> None:
        t = RecordingTransport()
        with pytest.raises(NetworkDisabledError):
            chain(t, cache=None, mode=Mode.CACHE_ONLY).complete("q")


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


class TestSecretHygiene:
    def test_config_holds_env_var_name_not_the_secret(self) -> None:
        assert P1.api_key_env == "P1_KEY"
        assert "test-key" not in repr(P1)

    def test_api_key_absent_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("P1_KEY", raising=False)
        assert P1.api_key() is None

    def test_failure_messages_do_not_leak_the_key(self, keys: None) -> None:
        t = RecordingTransport(
            HttpResult(401, {}, "bad key"), HttpResult(401, {}, "bad key")
        )
        with pytest.raises(AllProvidersFailedError) as exc:
            chain(t).complete("q")
        assert "test-key-1" not in str(exc.value)
        assert "test-key-2" not in str(exc.value)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_build_chain_defaults_are_ordered_and_documented(
        self, tmp_path: Path
    ) -> None:
        c = build_chain(cache_dir=tmp_path)
        assert [p.name for p in c.providers] == ["cerebras", "groq", "nvidia-nim"]
        assert c.mode is Mode.LIVE
        assert c.cache is not None

    def test_nvidia_is_last_and_flagged_dev_only(self) -> None:
        c = build_chain()
        last = c.providers[-1]
        assert last.name == "nvidia-nim"
        assert "DEV/TEST ONLY" in last.notes

    def test_cerebras_context_ceiling_recorded(self) -> None:
        cerebras = build_chain().providers[0]
        assert cerebras.max_context_tokens == 8192

    def test_temperature_defaults_to_zero(self, keys: None) -> None:
        t = RecordingTransport(HttpResult(200, ok_body()))
        chain(t).complete("q")
        assert t.calls[0][2]["temperature"] == 0.0

    def test_provider_unavailable_carries_status(self) -> None:
        exc = ProviderUnavailableError("p", "rate limited", status=429)
        assert exc.status == 429
        assert exc.provider == "p"
