"""Provider-agnostic LLM adapter with an ordered fallback chain.

Design constraints, in priority order:

1. **Nothing here can change a decision.** Every consumer of this module sits
   strictly downstream of :class:`~pramana.kernel.verdict.Verdict`. A provider
   outage, a rate limit, a prompt injection, or a malicious response degrades
   an *explanation*. It cannot alter an authorisation. See ADR-0004.

2. **No budget.** Free tiers only, and they are individually thin -- Groq is
   ~30 RPM / 1,000 RPD, Cerebras is 1M tokens/day with an 8K context ceiling.
   Independent providers have independent limits, so an ordered chain across
   them multiplies usable capacity rather than buying more.

3. **The demo must survive having no network.** A pre-warmed on-disk cache is
   consulted before any provider is contacted, and :class:`OfflineMode` refuses
   network access entirely. "Demo-by-WiFi" is a known way to lose a live pitch.

4. **Testable without an API key.** Every network call goes through an injected
   transport, so the whole chain -- including failover, backoff, and rate-limit
   handling -- is exercised in unit tests with no credentials and no sockets.

Groq, Cerebras, and NVIDIA NIM are all OpenAI-chat-completions compatible, so a
single adapter covers them; they differ only in base URL, model id, and key.
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S: Final = 20.0
DEFAULT_MAX_TOKENS: Final = 512
DEFAULT_TEMPERATURE: Final = 0.0
"""Zero by default. A verdict explanation that changes between runs is not
something a merchant or a dispute reviewer can rely on."""

_RETRYABLE_STATUS: Final = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
_HTTP_ERROR_FLOOR: Final = 400


class AIError(Exception):
    """Base class for adapter failures."""


class ProviderUnavailableError(AIError):
    """One provider failed. The chain may still recover."""

    def __init__(
        self, provider: str, reason: str, *, status: int | None = None
    ) -> None:
        self.provider = provider
        self.reason = reason
        self.status = status
        super().__init__(f"{provider}: {reason}")


class AllProvidersFailedError(AIError):
    """Every provider in the chain failed and the cache did not hold an answer.

    Callers must treat this as "no explanation available", never as "allow".
    """

    def __init__(self, failures: Sequence[ProviderUnavailableError]) -> None:
        self.failures = tuple(failures)
        detail = "; ".join(str(f) for f in failures) or "no providers configured"
        super().__init__(f"all providers failed: {detail}")


class MissingCredentialError(ProviderUnavailableError):
    """The provider is configured but its API key env var is unset."""


class NetworkDisabledError(AIError):
    """Offline mode was requested and the answer was not cached."""


class Mode(enum.StrEnum):
    """How aggressively the chain may reach the network."""

    LIVE = "live"
    """Cache first, then providers in order."""

    CACHE_ONLY = "cache_only"
    """Never touch the network. Used for rehearsed demos and CI."""

    REFRESH = "refresh"
    """Bypass the cache on read, but still write to it. Used to warm the cache."""


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """A completion plus the provenance needed to audit where it came from."""

    text: str
    provider: str
    model: str
    cached: bool
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "provider": self.provider,
            "model": self.model,
            "cached": self.cached,
            "latency_ms": round(self.latency_ms, 2),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
        }


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """A single OpenAI-compatible endpoint.

    ``api_key_env`` is the *name* of the environment variable, never the key
    itself. Nothing in this module accepts a literal secret, so a key cannot be
    committed by accident.
    """

    name: str
    base_url: str
    model: str
    api_key_env: str
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_context_tokens: int | None = None
    """Free-tier ceiling, where the provider imposes one. Cerebras is 8K."""

    reasoning_overhead_tokens: int = 0
    """Extra completion budget for reasoning models.

    ``gpt-oss-120b`` emits chain-of-thought into a separate ``reasoning`` field
    that is billed against ``max_tokens``. A 16-token budget was consumed
    entirely by reasoning and returned an empty ``content``. We add this on top
    of the caller's request so a small prose budget is not silently starved."""

    notes: str = ""

    def api_key(self) -> str | None:
        key = os.environ.get(self.api_key_env)
        return key.strip() or None if key else None


# Ordered by free-tier throughput and licence cleanliness. Cerebras leads on
# daily volume; Groq leads on latency; NVIDIA is last because its free tier is
# development/testing only and would need an AI Enterprise licence in
# production -- fine for a demo, not something to depend on.
CEREBRAS = ProviderConfig(
    name="cerebras",
    base_url="https://api.cerebras.ai/v1",
    model="gpt-oss-120b",
    api_key_env="CEREBRAS_API_KEY",
    max_context_tokens=8192,
    reasoning_overhead_tokens=768,
    notes="1M tokens/day, 14.4k req/day/model, 8K context. Verified 2026-08-23.",
)
GROQ = ProviderConfig(
    name="groq",
    base_url="https://api.groq.com/openai/v1",
    model="openai/gpt-oss-120b",
    api_key_env="GROQ_API_KEY",
    reasoning_overhead_tokens=768,
    notes="~30 RPM / 1000 RPD free tier; fastest first token. Verified 2026-08-23.",
)
NVIDIA_NIM = ProviderConfig(
    name="nvidia-nim",
    base_url="https://integrate.api.nvidia.com/v1",
    model="nvidia/llama-3.3-nemotron-super-49b-v1",
    api_key_env="NVIDIA_API_KEY",
    notes="DEV/TEST ONLY -- production use requires an AI Enterprise licence",
)

DEFAULT_CHAIN: Final = (CEREBRAS, GROQ, NVIDIA_NIM)


# ---------------------------------------------------------------------------
# Transport -- injected so the chain is testable without network or keys
# ---------------------------------------------------------------------------

Transport = Callable[[str, dict[str, str], dict[str, Any], float], "HttpResult"]


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    body: dict[str, Any]
    error: str | None = None


def httpx_transport(
    url: str, headers: dict[str, str], payload: dict[str, Any], timeout_s: float
) -> HttpResult:
    """Real network transport. Imported lazily so tests never need httpx."""
    import httpx  # noqa: PLC0415 -- lazy so tests need neither httpx nor network

    try:
        resp = httpx.post(url, headers=headers, json=payload, timeout=timeout_s)
    except Exception as exc:  # surfaced as a provider failure, never raised
        return HttpResult(status=0, body={}, error=f"{type(exc).__name__}: {exc}")
    try:
        body = resp.json()
    except ValueError:
        body = {}
    return HttpResult(
        status=resp.status_code,
        body=body,
        error=None if resp.status_code < _HTTP_ERROR_FLOOR else resp.text[:300],
    )


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PromptKey:
    """Identity of a request, for caching.

    Deliberately excludes the provider and model. A rehearsed demo should
    replay from cache regardless of which provider originally answered, and
    regardless of which providers happen to be reachable on the day. The
    provenance of the cached answer is preserved in the stored record, so the
    trade-off is visible rather than hidden.
    """

    system: str
    prompt: str
    max_tokens: int
    temperature: float

    def digest(self) -> str:
        payload = json.dumps(
            {
                "system": self.system,
                "prompt": self.prompt,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResponseCache:
    """Content-addressed on-disk cache. One JSON file per entry."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)

    def _path(self, key: PromptKey) -> Path:
        return self.directory / f"{key.digest()}.json"

    def get(self, key: PromptKey) -> LLMResponse | None:
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            logger.warning("cache entry unreadable, ignoring: %s", path.name)
            return None
        return LLMResponse(
            text=raw["text"],
            provider=raw.get("provider", "cache"),
            model=raw.get("model", "unknown"),
            cached=True,
            latency_ms=0.0,
            prompt_tokens=raw.get("prompt_tokens"),
            completion_tokens=raw.get("completion_tokens"),
        )

    def put(self, key: PromptKey, response: LLMResponse) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            record = response.to_dict()
            record["cached"] = False  # provenance: how it was first obtained
            self._path(key).write_text(
                json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            # A cache write failure must never fail the caller.
            logger.warning("cache write failed: %s", exc)

    def __len__(self) -> int:
        if not self.directory.is_dir():
            return 0
        return sum(1 for _ in self.directory.glob("*.json"))


# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------


@dataclass
class ProviderChain:
    """Try the cache, then each provider in order, then give up honestly."""

    providers: Sequence[ProviderConfig] = DEFAULT_CHAIN
    cache: ResponseCache | None = None
    mode: Mode = Mode.LIVE
    transport: Transport = httpx_transport
    max_retries: int = 2
    backoff_base_s: float = 0.5
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.perf_counter
    last_failures: list[ProviderUnavailableError] = field(default_factory=list)

    def available(self) -> tuple[ProviderConfig, ...]:
        """Providers whose credential is actually present in the environment."""
        return tuple(p for p in self.providers if p.api_key() is not None)

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> LLMResponse:
        """Return a completion, or raise. Never returns a partial result."""
        key = PromptKey(
            system=system,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        if self.cache is not None and self.mode is not Mode.REFRESH:
            hit = self.cache.get(key)
            if hit is not None:
                logger.debug("cache hit %s", key.digest()[:12])
                return hit

        if self.mode is Mode.CACHE_ONLY:
            raise NetworkDisabledError(
                f"offline mode and no cached answer for {key.digest()[:12]}"
            )

        failures: list[ProviderUnavailableError] = []
        for config in self.providers:
            try:
                response = self._call(config, key)
            except ProviderUnavailableError as exc:
                logger.info("provider %s unavailable: %s", config.name, exc.reason)
                failures.append(exc)
                continue
            if self.cache is not None:
                self.cache.put(key, response)
            self.last_failures = failures
            return response

        self.last_failures = failures
        raise AllProvidersFailedError(failures)

    def _call(self, config: ProviderConfig, key: PromptKey) -> LLMResponse:
        api_key = config.api_key()
        if api_key is None:
            raise MissingCredentialError(
                config.name, f"{config.api_key_env} is not set"
            )

        messages: list[dict[str, str]] = []
        if key.system:
            messages.append({"role": "system", "content": key.system})
        messages.append({"role": "user", "content": key.prompt})

        payload: dict[str, Any] = {
            "model": config.model,
            "messages": messages,
            "max_tokens": (
                min(key.max_tokens, config.max_tokens)
                + config.reasoning_overhead_tokens
            ),
            "temperature": key.temperature,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        url = f"{config.base_url.rstrip('/')}/chat/completions"

        last: ProviderUnavailableError | None = None
        for attempt in range(self.max_retries + 1):
            started = self.clock()
            result = self.transport(url, headers, payload, config.timeout_s)
            elapsed_ms = (self.clock() - started) * 1000.0

            if result.status == 0:
                last = ProviderUnavailableError(
                    config.name, result.error or "transport error"
                )
            elif result.status in _RETRYABLE_STATUS:
                last = ProviderUnavailableError(
                    config.name,
                    f"HTTP {result.status}: {result.error or 'retryable'}",
                    status=result.status,
                )
            elif result.status >= _HTTP_ERROR_FLOOR:
                # Non-retryable: bad key, bad model, malformed request.
                raise ProviderUnavailableError(
                    config.name,
                    f"HTTP {result.status}: {result.error or 'client error'}",
                    status=result.status,
                )
            else:
                return self._parse(config, result, elapsed_ms)

            if attempt < self.max_retries:
                self.sleep(self.backoff_base_s * (2**attempt))

        raise last or ProviderUnavailableError(config.name, "exhausted retries")

    @staticmethod
    def _parse(
        config: ProviderConfig, result: HttpResult, elapsed_ms: float
    ) -> LLMResponse:
        try:
            choices = result.body["choices"]
            text = choices[0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderUnavailableError(
                config.name, f"unparseable response shape: {exc}"
            ) from exc
        if not isinstance(text, str) or not text.strip():
            message = choices[0].get("message", {}) if choices else {}
            if message.get("reasoning"):
                raise ProviderUnavailableError(
                    config.name,
                    "empty completion: the reasoning field consumed the whole "
                    "token budget. Raise max_tokens or reasoning_overhead_tokens.",
                )
            raise ProviderUnavailableError(config.name, "empty completion")

        usage = result.body.get("usage") or {}
        return LLMResponse(
            text=text.strip(),
            provider=config.name,
            model=result.body.get("model", config.model),
            cached=False,
            latency_ms=elapsed_ms,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )


def build_chain(
    *,
    cache_dir: Path | str | None = None,
    mode: Mode = Mode.LIVE,
    providers: Iterable[ProviderConfig] | None = None,
) -> ProviderChain:
    """Construct the default chain with a cache rooted at ``cache_dir``."""
    return ProviderChain(
        providers=tuple(providers) if providers is not None else DEFAULT_CHAIN,
        cache=ResponseCache(cache_dir) if cache_dir is not None else None,
        mode=mode,
    )
