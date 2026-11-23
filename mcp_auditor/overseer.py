"""Overseer prompt + response parsing (no LLM client — hosts inject callables)."""
from __future__ import annotations

import json
import re
from typing import Any, Awaitable, Callable, Sequence, Union

from .types import ClearanceLevel, McpToolDescriptor

# Async or sync overseer: (tools) -> (verdict, rationale)
OverseerFn = Callable[
    [Sequence[McpToolDescriptor]],
    Union[Awaitable[tuple[str, str]], tuple[str, str]],
]


def build_overseer_prompt(tools: Sequence[McpToolDescriptor]) -> tuple[str, str]:
    system = (
        "You are a security overseer auditing the tool surface of a Model Context "
        "Protocol (MCP) server before it is allowed to run inside a zero-trust agent "
        "host. Evaluate the BLAST RADIUS of the combined tools: could they exfiltrate "
        "data to an external destination, move money, delete or overwrite production "
        "resources, execute arbitrary shell/code, or escalate privileges? "
        'Reply ONLY with strict JSON: {"verdict":"SAFE|REVIEW|MALICIOUS",'
        '"rationale":"one sentence"}. '
        "SAFE = strictly read-only / low blast radius. "
        "REVIEW = mutating but legitimate; should require human approval. "
        "MALICIOUS = the surface looks designed to exfiltrate, defraud, or destroy."
    )
    user = json.dumps(
        {
            "tools": [
                {"name": tool.name, "description": tool.description}
                for tool in tools
            ]
        },
        ensure_ascii=True,
        sort_keys=True,
    )
    return system, user


def parse_overseer_text(text: str) -> tuple[str, str]:
    """Parse an overseer reply into ``(verdict, rationale)``.

    Only a strict JSON object can yield ``SAFE``. Free text is never read as SAFE,
    because words like "unsafe" or "not safe" contain it; a free-text mention of
    MALICIOUS is honoured (it only makes the result stricter), anything else is
    REVIEW.
    """
    raw = text.strip() if isinstance(text, str) else ""
    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if match is not None:
        try:
            payload = json.loads(match.group(0))
            verdict = str(payload.get("verdict") or "").strip().upper()
            rationale = str(payload.get("rationale") or "").strip()
            if verdict in {"SAFE", "REVIEW", "MALICIOUS"}:
                return verdict, rationale or "no rationale provided"
        except json.JSONDecodeError:
            pass
    if "MALICIOUS" in raw.upper():
        return "MALICIOUS", raw[:280]
    return "REVIEW", raw[:280] or "overseer returned an unparseable response"


def extract_response_text(response: Any) -> str:
    """Best-effort extract of chat-completion style content from dict/object."""
    choices = (
        response.get("choices", [])
        if isinstance(response, dict)
        else getattr(response, "choices", [])
    )
    if not choices:
        return ""
    choice = choices[0]
    if isinstance(choice, dict):
        message = choice.get("message")
        content = message.get("content") if isinstance(message, dict) else None
    else:
        message = getattr(choice, "message", None)
        content = None if message is None else getattr(message, "content", None)
    return content if isinstance(content, str) else ""


def overseer_floor(verdict: str) -> ClearanceLevel:
    """Map overseer verdict → clearance floor.

    UNAVAILABLE / SKIPPED / REVIEW → DRAFT_ONLY (human review), never open.
    MALICIOUS → BLOCKED. SAFE → READ_ONLY (may still be raised by static classify).
    """
    v = verdict.strip().upper() if isinstance(verdict, str) else ""
    if v == "MALICIOUS":
        return ClearanceLevel.BLOCKED
    if v == "SAFE":
        return ClearanceLevel.READ_ONLY
    return ClearanceLevel.DRAFT_ONLY
