"""jev_ask handler — lets the model ask for a typed judgment itself."""

from __future__ import annotations

import json

from .gate import client_for, log_decision, settings_for
from .jev import JevClient

_CTX = None  # bound by register(): the tool handler receives no ctx of its own


def bind(ctx) -> None:
    """Share the plugin ctx with the tool (called once from register())."""
    global _CTX
    _CTX = ctx


def _client_and_log_path() -> tuple:
    """Client built from the shared settings; default client without a ctx."""
    if _CTX is None:
        return JevClient(), None
    try:
        s = settings_for(_CTX)
        return client_for(s), s.get("log_path") or None
    except Exception:
        return JevClient(), None


def jev_ask(args: dict, **kwargs) -> str:
    """Return JSON string: answers + confidence, or a fail-open note. Never raises."""
    state = args.get("state", "")
    raw_questions = args.get("questions", {})
    if isinstance(raw_questions, str):
        try:
            questions = json.loads(raw_questions)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"questions is not valid JSON: {exc}"})
    else:
        questions = raw_questions
    if not isinstance(questions, dict) or not questions:
        return json.dumps({"error": "questions must be a non-empty JSON object"})

    client, log_path = _client_and_log_path()
    result = client.evaluate(state, questions)
    if not result:
        reason = getattr(client, "last_error", None) or "unknown"
        log_decision(
            log_path, {"source": "ask", "outcome": "fail_open", "reason": reason}
        )
        return json.dumps(
            {
                "error": f"Jev unavailable ({reason})",
                "note": "fail-open: proceed without this judgment",
            }
        )

    log_decision(
        log_path,
        {
            "source": "ask",
            "outcome": "ok",
            "questions": list(questions.keys()),
            "latency_ms": result.get("latency_ms"),
            "cost": result.get("cost"),
        },
    )
    return json.dumps(
        {
            "answers": result["answers"],
            "confidence": result.get("confidence", {}),
            "cost_usd": result.get("cost"),
        },
        ensure_ascii=False,
    )
