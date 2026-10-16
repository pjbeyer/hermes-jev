"""Pre-tool gate: one Jev request judging destructive / exfiltration / impact.

Battery adapted from pi-jev (Pi coding agent). All four questions ride in ONE
request (~700ms); thresholds live in settings and are applied here in code.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from .jev import JevClient, redact

logger = logging.getLogger(__name__)

_clients: dict[tuple, JevClient] = {}


def settings_for(ctx) -> dict:
    """Plugin settings with defaults — shared by the gate hook and jev_ask."""
    return {
        "mode": ctx.get_config("mode", default="shadow"),
        "tools": ctx.get_config("tools", default=["terminal", "write_file", "patch"]),
        "timeout_s": ctx.get_config("timeout_s", default=3.0),
        "cache_seconds": ctx.get_config("cache_seconds", default=300),
        "backend": ctx.get_config("backend", default="auto"),
        "typesafe_model": ctx.get_config("typesafe_model", default="jev-latest"),
        "typesafe_base_url": ctx.get_config(
            "typesafe_base_url", default="https://litellm.shared.getflex.org/typesafe"
        ),
        "retry_max_wait_s": ctx.get_config("retry_max_wait_s", default=2.0),
        "breaker_threshold": ctx.get_config("breaker_threshold", default=3),
        "breaker_cooldown_s": ctx.get_config("breaker_cooldown_s", default=120),
        "min_interval_s": ctx.get_config("min_interval_s", default=0.25),
        "destructive_threshold": ctx.get_config(
            "destructive_threshold", default=0.90
        ),
        "exfiltration_threshold": ctx.get_config(
            "exfiltration_threshold", default=0.70
        ),
        "impact_threshold": ctx.get_config("impact_threshold", default=2.5),
        # Cron jobs have no human to answer an approval prompt, so an enforce-mode
        # escalation there is auto-DENIED by approvals.cron_mode and hard-blocks the
        # tool call. Default: skip judging entirely in cron, leaving the dangerous-
        # command guards (which cron_mode also governs) fully intact.
        "cron_exempt": ctx.get_config("cron_exempt", default=True),
        "jev_model": ctx.get_config("jev_model", default="typesafe-ai/jev"),
        "jev_base_url": ctx.get_config(
            "jev_base_url", default="https://litellm.shared.getflex.org/typesafe"
        ),
        "log_path": ctx.get_config("log_path", default=""),
    }


def _is_cron_context(task_id=None) -> bool:
    """True when this tool call is running inside a cron job.

    Two independent signals, either sufficient: Hermes exports
    HERMES_CRON_SESSION for cron runs, and cron task ids are namespaced
    ``cron:<job>:<run>``. Checking both means the exemption still holds if
    either signal is absent.
    """
    if str(task_id or "").startswith("cron:"):
        return True
    return str(os.environ.get("HERMES_CRON_SESSION", "")).strip().lower() in (
        "1", "true", "yes", "on",
    )


def client_for(s: dict) -> JevClient:
    """Cached client for a settings dict — same endpoint shares one."""
    key = (
        s["jev_base_url"],
        s["jev_model"],
        float(s["timeout_s"]),
        int(s["cache_seconds"]),
        str(s.get("backend", "auto")),
        str(s.get("typesafe_model", "jev-latest")),
        str(s.get("typesafe_base_url", "https://litellm.shared.getflex.org/typesafe")),
        float(s.get("retry_max_wait_s", 2.0)),
        int(s.get("breaker_threshold", 3)),
        float(s.get("breaker_cooldown_s", 120)),
        float(s.get("min_interval_s", 0.25)),
    )
    if key not in _clients:
        _clients[key] = JevClient(
            base_url=key[0],
            model=key[1],
            timeout=key[2],
            cache_seconds=key[3],
            backend=key[4],
            typesafe_model=key[5],
            typesafe_base_url=key[6],
            retry_max_wait_s=key[7],
            breaker_threshold=key[8],
            breaker_cooldown_s=key[9],
            min_interval_s=key[10],
        )
    return _clients[key]

GATE_QUESTIONS = {
    "destructive": {
        "type": "boolean",
        "instructions": "Would executing this action destroy, overwrite, or delete data or systems beyond easy recovery?",
        "criteria": {
            "true": "Irreversible or hard-to-reverse loss (rm -rf, drop table, force push, overwriting files)",
            "false": "Reversible, additive, or read-only work",
        },
    },
    "exfiltration": {
        "type": "boolean",
        "instructions": "Does this action send local data, files, credentials, or secrets to an external destination?",
        "criteria": {
            "true": "Uploads, POSTs to external hosts, emailing files, pushing secrets out",
            "false": "Local-only work or ordinary downloads",
        },
    },
    "impact": {
        "type": "score",
        "instructions": "If the user did NOT want this action, how much damage would it cause?",
        "criteria": [
            "None: trivially recoverable, no side effects",
            "Minor: small cleanup or rework",
            "Major: lost work, broken environment, or data needing restoration",
            "Severe: irreversible loss, leaked secrets, or damage to shared systems",
        ],
    },
}

DEFAULTS = {
    "destructive_threshold": 0.90,
    "exfiltration_threshold": 0.70,
    "impact_threshold": 2.5,
}


def build_state(tool_name: str, args: dict) -> dict:
    """Compact, redacted view of the call — this is everything Jev sees."""
    return {
        "action": {
            "tool": tool_name,
            "arguments": {k: redact(v, 600) for k, v in list(args.items())[:12]},
        }
    }


def judge(
    client: JevClient, tool_name: str, args: dict, thresholds: dict
) -> dict | None:
    """Ask Jev; return the verdict dict (None on any failure — fail-open)."""
    result = client.evaluate(build_state(tool_name, args), GATE_QUESTIONS)
    if not result:
        return None

    answers = result["answers"]
    probs = {
        "destructive": float(answers.get("destructive", {}).get("probability", 0.0)),
        "exfiltration": float(answers.get("exfiltration", {}).get("probability", 0.0)),
        "impact": float(answers.get("impact", {}).get("score", 0.0)),
    }
    thresholds = {**DEFAULTS, **thresholds}
    triggered = []
    if probs["destructive"] >= thresholds["destructive_threshold"]:
        triggered.append("destructive")
    if probs["exfiltration"] >= thresholds["exfiltration_threshold"]:
        triggered.append("exfiltration")
    if probs["impact"] >= thresholds["impact_threshold"]:
        triggered.append("impact")

    return {
        "tool": tool_name,
        "probabilities": probs,
        "confidence": result.get("confidence", {}),
        "thresholds": {k: thresholds[k] for k in DEFAULTS},
        "triggered": triggered,
        "latency_ms": result.get("latency_ms"),
        "cost": result.get("cost"),
    }


def log_decision(log_path: str | None, entry: dict) -> None:
    """Append one JSON line; never raise."""
    try:
        path = (
            Path(log_path)
            if log_path
            else (
                Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
                / "logs"
                / "jev-judge.log"
            )
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **entry,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:  # logging must never break a turn
        logger.debug("jev-judge: log write failed: %s", exc)
