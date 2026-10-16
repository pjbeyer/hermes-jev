"""Jev client — TypeSafe System One, direct or via the Vercel AI Gateway.

Pure stdlib. Backend selection (`backend: auto|typesafe|gateway`, default
`auto`): TypeSafe direct when TYPESAFE_API_KEY is present, else the gateway
when AI_GATEWAY_API_KEY is present, else silent. Every failure path returns
None (fail-open).
"""

from __future__ import annotations

import email.utils
import hashlib
import json
import logging
import math
import os
import re
import time
import urllib.error
import urllib.request
from datetime import timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://litellm.shared.getflex.org/typesafe"
DEFAULT_MODEL = "typesafe-ai/jev"
DEFAULT_TYPESAFE_BASE_URL = "https://litellm.shared.getflex.org/typesafe"
DEFAULT_TYPESAFE_MODEL = "jev-latest"
PROTOCOL_VERSION = "0.0.1"
SPEC_VERSION = "4"

RATE_LIMIT_CODES = (429, 529)

# Hard ceiling for one attempt: the loader fail-closes pre_tool_call past
# hook_callback_timeout (default 30s), so an unbounded timeout_s would turn
# the documented fail-open into a blocked tool. Worst case per call stays
# ~2x this + retry_max_wait_s, under that budget.
MAX_TIMEOUT_S = 10.0

# Cap for the per-process response cache: distinct turns each insert one
# entry, so size must be bounded even though entries also expire by TTL.
CACHE_MAX_ENTRIES = 256

# Per-process state, keyed by endpoint URL: client instances are cached per
# settings (or rebuilt per call), but pacing and breaker must survive that.
_PACE_LAST: dict[str, float] = {}  # endpoint -> monotonic time of last attempt
_BREAKER: dict[str, list] = {}  # endpoint -> [consecutive 429/529s, open-until]

# Known secret prefixes: sk- (OpenAI-style), gh?_ / github_pat_ (GitHub),
# AKIA (AWS access key id), xox* (Slack), AIza (Google), vck_ (Vercel).
_PREFIX_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{4,}"
    r"|gh[a-z]?_[A-Za-z0-9]{8,}"
    r"|github_pat_[A-Za-z0-9_-]{8,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[a-z]*-[A-Za-z0-9-]+"
    r"|AIza[A-Za-z0-9_-]{8,}"
    r"|vck_[A-Za-z0-9_-]{8,})"
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/=]+", re.IGNORECASE)
_BASIC_RE = re.compile(r"Basic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)
_PEM_RE = re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*-----")
_JWT_RE = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")
# Cap-and-flag fallback: any long spaceless run is treated as a secret.
_GENERIC_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def redact(value, limit: int = 4000) -> str:
    """Stringify, mask key-shaped tokens, truncate."""
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, ensure_ascii=False, default=str)
    )
    text = _PEM_RE.sub("[REDACTED]", text)
    text = _BEARER_RE.sub("[REDACTED]", text)
    text = _BASIC_RE.sub("[REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED]", text)
    text = _PREFIX_RE.sub("[REDACTED]", text)
    text = _GENERIC_RE.sub("[REDACTED]", text)
    if len(text) > limit:
        text = text[:limit] + f"...(+{len(text) - limit} chars)"
    return text


def _env_key(name: str) -> str | None:
    key = os.environ.get(name)
    if key and key.strip():
        return key.strip()
    env_file = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / ".env"
    try:
        m = re.search(
            rf'^{name}=["\']?([^"\'\n]+)', env_file.read_text(), re.MULTILINE
        )
        return m.group(1).strip() if m else None
    except OSError:
        return None


def api_key() -> str | None:
    return _env_key("AI_GATEWAY_API_KEY")


def typesafe_api_key() -> str | None:
    return _env_key("TYPESAFE_API_KEY")


def resolve_backend(backend: str = "auto") -> str | None:
    """Pick 'typesafe' | 'gateway' | None (no key for the wanted backend)."""
    want = (backend or "auto").strip().lower()
    if want not in ("auto", "typesafe", "gateway"):
        want = "auto"
    has_ts, has_gw = bool(typesafe_api_key()), bool(api_key())
    if want == "typesafe":
        return "typesafe" if has_ts else None
    if want == "gateway":
        return "gateway" if has_gw else None
    if has_ts:
        return "typesafe"
    return "gateway" if has_gw else None


def to_typesafe_questions(questions: dict) -> dict:
    """Internal boolean -> TypeSafe noul; choice/score pass through."""
    out = {}
    for qid, question in (questions or {}).items():
        question = dict(question or {})
        if question.get("type") == "boolean":
            out[qid] = {
                "type": "noul",
                "instructions": question.get("instructions", ""),
            }
            if "criteria" in question:
                out[qid]["criteria"] = question["criteria"]
        else:
            out[qid] = question
    return out


def _num(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_typesafe_answers(answers: dict) -> dict:
    """TypeSafe noul -> internal {probability}; choice/score already internal."""
    out = {}
    for qid, answer in (answers or {}).items():
        if not isinstance(answer, dict):
            continue
        if answer.get("type") == "noul":
            out[qid] = {"type": "boolean", "probability": _num(answer.get("noul"))}
        else:
            out[qid] = answer
    return out


def typesafe_confidence(answers: dict) -> dict:
    """Per-answer inline confidence (noul answers carry none)."""
    confidence = {}
    for qid, answer in (answers or {}).items():
        if isinstance(answer, dict) and "confidence" in answer:
            confidence[qid] = _num(answer["confidence"])
    return confidence


def retry_after_s(value, now_wall: float) -> float | None:
    """Parse a Retry-After header: seconds or an HTTP date. Garbage -> None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        wait = float(text)
    except ValueError:
        pass
    else:
        return wait if math.isfinite(wait) else None
    try:
        moment = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    delta = moment.timestamp() - now_wall
    return delta if math.isfinite(delta) else None


class JevClient:
    """One call = one request = typed answers (choice / score / boolean)."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 3.0,
        cache_seconds: int = 300,
        backend: str = "auto",
        typesafe_model: str = DEFAULT_TYPESAFE_MODEL,
        typesafe_base_url: str = DEFAULT_TYPESAFE_BASE_URL,
        retry_max_wait_s: float = 2.0,
        breaker_threshold: int = 3,
        breaker_cooldown_s: float = 120,
        min_interval_s: float = 0.25,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = min(float(timeout), MAX_TIMEOUT_S)
        self.cache_seconds = int(cache_seconds)
        self.backend = backend
        self.typesafe_model = typesafe_model
        self.typesafe_base_url = typesafe_base_url.rstrip("/")
        self.retry_max_wait_s = float(retry_max_wait_s)
        self.breaker_threshold = int(breaker_threshold)
        self.breaker_cooldown_s = float(breaker_cooldown_s)
        self.min_interval_s = float(min_interval_s)
        self._cache: dict[str, tuple[float, dict]] = {}
        # Why the last evaluate() failed, for fail_open diagnostics. None when
        # the last call succeeded. Every fail-open path sets this; without it a
        # fail_open log line carries no cause and cannot be triaged.
        self.last_error: str | None = None
        # Seams for offline tests (transport stub, clock mock).
        self._urlopen = urllib.request.urlopen
        self._clock = time.monotonic
        self._sleep = time.sleep

    def _resolve(self) -> tuple[str | None, str | None]:
        backend = resolve_backend(self.backend)
        if backend == "typesafe":
            return backend, typesafe_api_key()
        if backend == "gateway":
            return backend, api_key()
        return None, None

    def _breaker_open(self, endpoint: str) -> bool:
        state = _BREAKER.get(endpoint)
        return (
            state is not None
            and state[0] >= self.breaker_threshold
            and self._clock() < state[1]
        )

    def _note_ratelimit(self, endpoint: str) -> None:
        state = _BREAKER.get(endpoint) or [0, 0.0]
        state[0] += 1
        if state[0] >= self.breaker_threshold:
            state[1] = self._clock() + self.breaker_cooldown_s
        _BREAKER[endpoint] = state

    def _note_success(self, endpoint: str) -> None:
        _BREAKER.pop(endpoint, None)

    def _pace(self, endpoint: str) -> None:
        """Space outgoing calls by min_interval_s (per process, per endpoint)."""
        if self.min_interval_s <= 0:
            _PACE_LAST[endpoint] = self._clock()
            return
        now = self._clock()
        last = _PACE_LAST.get(endpoint)
        if last is not None and now - last < self.min_interval_s:
            self._sleep(self.min_interval_s - (now - last))
            now = self._clock()
        _PACE_LAST[endpoint] = now

    def _send(self, url: str, data: bytes, headers: dict):
        """One paced POST, returning the parsed JSON body. Raises."""
        self._pace(url)
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        with self._urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def _fail(self, reason: str):
        """Record why a call failed (for fail_open diagnostics) and return None."""
        self.last_error = reason
        logger.debug("jev-judge: fail-open (%s)", reason)
        return None

    def _post_json(self, url: str, data: bytes, headers: dict):
        """POST with a single rate-limit retry. Returns the body or None."""
        try:
            body = self._send(url, data, headers)
        except urllib.error.HTTPError as exc:
            if exc.code not in RATE_LIMIT_CODES:
                return self._fail(f"http_{exc.code}")
            self._note_ratelimit(url)
            wait = retry_after_s(
                exc.headers.get("retry-after") if exc.headers else None,
                time.time(),
            )
            if wait is None or wait > self.retry_max_wait_s:
                return self._fail(f"ratelimit_no_retry_{exc.code}")
            if wait > 0:
                self._sleep(wait)
            try:
                body = self._send(url, data, headers)
            except urllib.error.HTTPError as exc2:
                # Counted once per evaluate (first 429/529 above); no double note.
                return self._fail(f"ratelimit_retry_failed_{exc2.code}")
            except Exception as exc2:  # timeout, network, parse — fail-open
                return self._fail(f"retry_{type(exc2).__name__}")
        except Exception as exc:  # timeout, 5xx, network, parse — always fail-open
            return self._fail(f"{type(exc).__name__}")
        self._note_success(url)
        return body

    def evaluate(self, state, questions: dict) -> dict | None:
        """Return {"answers", "confidence", "cost", "latency_ms", "usage"} or None."""
        self.last_error = None
        backend, key = self._resolve()
        if backend is None or not key:
            return self._fail(
                "no_backend_key" if backend is None else "empty_key"
            )

        cache_key = hashlib.sha256(
            json.dumps(
                [backend, self.model, self.typesafe_model, state, questions],
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            ).encode()
        ).hexdigest()
        now = time.time()
        hit = self._cache.get(cache_key)
        if hit and hit[0] > now:
            return hit[1]

        if backend == "typesafe":
            endpoint = f"{self.typesafe_base_url}/v1/systemone"
            payload = json.dumps(
                {
                    "state": state,
                    "model": self.typesafe_model,
                    "questions": to_typesafe_questions(questions),
                },
                ensure_ascii=False,
                default=str,
            ).encode()
            headers = {
                "Authorization": f"Bearer {key}",
                "content-type": "application/json",
            }
        else:
            endpoint = f"{self.base_url}/evaluation-model"
            payload = json.dumps(
                {"state": state, "questions": questions},
                ensure_ascii=False,
                default=str,
            ).encode()
            headers = {
                "Authorization": f"Bearer {key}",
                "ai-gateway-protocol-version": PROTOCOL_VERSION,
                "ai-evaluation-model-specification-version": SPEC_VERSION,
                "ai-model-id": self.model,
                "content-type": "application/json",
            }
        if self._breaker_open(endpoint):
            return self._fail("breaker_open")
        started = self._clock()
        body = self._post_json(endpoint, payload, headers)
        if body is None:
            return None  # _post_json already recorded last_error

        if backend == "typesafe":
            raw_answers = body.get("answers", {})
            # The gateway may return provider metadata under either casing:
            # Vercel uses camelCase ("providerMetadata"); the Flex gateway uses
            # snake_case ("provider_metadata"). Read both, or cost telemetry
            # silently disappears (all costs logged as null).
            pmeta = body.get("provider_metadata") or body.get("providerMetadata") or {}
            gw_meta = pmeta.get("gateway", {}) or {}
            ts_meta = pmeta.get("typesafe", {}) or {}
            result = {
                "answers": normalize_typesafe_answers(raw_answers),
                "confidence": typesafe_confidence(raw_answers) or ts_meta.get(
                    "confidence", {}
                ),
                # gatewayCost includes the ZDR surcharge; marketCost is inference only.
                "cost": gw_meta.get("gatewayCost") or gw_meta.get("cost"),
                "usage": body.get("usage"),
                "latency_ms": round((self._clock() - started) * 1000),
            }
        else:
            result = {
                "answers": body.get("answers", {}),
                "confidence": (
                    body.get("providerMetadata", {}).get("typesafe", {}) or {}
                ).get("confidence", {}),
                "cost": (body.get("providerMetadata", {}).get("gateway", {}) or {}).get(
                    "cost"
                ),
                "usage": body.get("usage"),
                "latency_ms": round((self._clock() - started) * 1000),
            }
        self._cache[cache_key] = (now + self.cache_seconds, result)
        if len(self._cache) > CACHE_MAX_ENTRIES:
            self._cache.pop(next(iter(self._cache)))  # oldest-inserted first
        return result
