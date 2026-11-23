"""audit_tool_surface(_sync), the overseer hook and its helpers."""
from __future__ import annotations

import asyncio
import json
import types

import pytest

from mcp_auditor import (
    ClearanceLevel,
    McpToolDescriptor,
    ServerAuditReport,
    audit_tool_surface,
    audit_tool_surface_sync,
    build_overseer_prompt,
    extract_response_text,
    overseer_floor,
    parse_overseer_text,
)

R, D, B = ClearanceLevel.READ_ONLY, ClearanceLevel.DRAFT_ONLY, ClearanceLevel.BLOCKED
READ = [McpToolDescriptor(name="list_orders"), McpToolDescriptor(name="get_record")]


def _audit(overseer, tools=READ):
    return asyncio.run(audit_tool_surface(tools, overseer=overseer))


def test_safe_overseer_on_read_only_surface_gives_read_only():
    def safe(_tools):
        return "SAFE", "read-only"

    report = _audit(safe)
    assert report.overseer_verdict == "SAFE"
    assert report.recommended_clearance is R


def test_async_overseer_is_awaited():
    async def safe(_tools):
        return "safe", "ok"

    assert _audit(safe).recommended_clearance is R


def test_safe_overseer_cannot_lower_static_clearance():
    def safe(_tools):
        return "SAFE", "trust me"

    report = _audit(safe, [McpToolDescriptor(name="delete_all")])
    assert report.recommended_clearance is D


def test_malicious_overseer_blocks():
    def bad(_tools):
        return "MALICIOUS", "exfil"

    assert _audit(bad).recommended_clearance is B


@pytest.mark.parametrize(
    "result",
    ["SAFE", ("SAFE",), ("SAFE", "x", "y"), (None, None), (1, "x"), {"verdict": "SAFE"},
     ("SAFE_ENOUGH", "x"), ("", ""), None],
)
def test_garbage_overseer_results_fail_closed(result):
    def garbage(_tools):
        return result

    report = _audit(garbage)
    assert report.overseer_verdict == "UNAVAILABLE"
    assert report.recommended_clearance is D
    assert isinstance(report.overseer_verdict, str)


def test_raising_overseer_fails_closed():
    async def boom(_tools):
        raise RuntimeError("down")

    report = _audit(boom)
    assert report.overseer_verdict == "UNAVAILABLE"
    assert report.recommended_clearance is D


def test_empty_surface_is_draft_only_and_skips_overseer():
    called = []

    def safe(tools):
        called.append(tools)
        return "SAFE", "ok"

    report = _audit(safe, [])
    assert report.recommended_clearance is D
    assert called == []


def test_sync_audit_uses_an_injected_overseer():
    """Bug: the sync entry point silently ignored ``overseer=`` unless use_overseer=True."""
    report = audit_tool_surface_sync(READ, overseer=lambda _t: ("SAFE", "ok"))
    assert report.overseer_verdict == "SAFE"
    assert report.recommended_clearance is R
    skipped = audit_tool_surface_sync(READ, overseer=lambda _t: ("SAFE", "ok"), use_overseer=False)
    assert skipped.recommended_clearance is D


def test_sync_audit_refuses_inside_a_running_loop():
    async def inner():
        audit_tool_surface_sync(READ, overseer=lambda _t: ("SAFE", "ok"))

    with pytest.raises(RuntimeError, match="event loop"):
        asyncio.run(inner())


def test_report_round_trip_and_tool_lookup():
    report = audit_tool_surface_sync([McpToolDescriptor(name="get_x"), McpToolDescriptor(name="put_x")])
    again = ServerAuditReport.from_dict(report.to_dict())
    assert again.to_dict() == report.to_dict()
    assert again.clearance_for_tool("get_x") is R
    assert again.clearance_for_tool("nope") is D
    assert again.tool_count == 2
    assert "2 tool(s)" in again.summary


def test_report_lookup_duplicates_and_garbage():
    data = {
        "recommended_clearance": "READ_ONLY",
        "tools": [
            {"name": "x", "clearance": "READ_ONLY"},
            {"name": "x", "clearance": "BLOCKED"},
            "garbage",
            None,
        ],
    }
    report = ServerAuditReport.from_dict(data)
    assert report.tool_count == 2
    assert report.clearance_for_tool("x") is B
    assert report.clearance_for_tool("") is D


# ----------------------------------------------------------------- overseer helpers


@pytest.mark.parametrize(
    "text, verdict",
    [
        ('{"verdict":"SAFE","rationale":"read-only"}', "SAFE"),
        ('Sure! {"verdict": "review", "rationale": "writes"} done', "REVIEW"),
        ('{"verdict":"MALICIOUS","rationale":"exfil"}', "MALICIOUS"),
        ("UNSAFE: this server can delete production data", "REVIEW"),
        ("This is not safe.", "REVIEW"),
        ("SAFE", "REVIEW"),
        ("looks malicious to me", "MALICIOUS"),
        ('{"verdict":"PROBABLY_SAFE"}', "REVIEW"),
        ("{not json", "REVIEW"),
        ("", "REVIEW"),
        (None, "REVIEW"),
    ],
)
def test_parse_overseer_text(text, verdict):
    """Bug: free text containing "SAFE" (including "UNSAFE") parsed as SAFE."""
    got, rationale = parse_overseer_text(text)
    assert got == verdict
    assert rationale


@pytest.mark.parametrize(
    "verdict, level",
    [("SAFE", R), (" safe ", R), ("REVIEW", D), ("UNAVAILABLE", D), ("SKIPPED", D),
     ("MALICIOUS", B), ("", D), (None, D), (1, D), (b"SAFE", D)],
)
def test_overseer_floor(verdict, level):
    assert overseer_floor(verdict) is level


def test_build_overseer_prompt_is_deterministic_json():
    system, user = build_overseer_prompt([McpToolDescriptor(name="t", description="dé")])
    assert "SAFE|REVIEW|MALICIOUS" in system
    assert json.loads(user) == {"tools": [{"name": "t", "description": "dé"}]}
    assert user.isascii()


def test_extract_response_text():
    assert extract_response_text({"choices": [{"message": {"content": "hi"}}]}) == "hi"
    obj = types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="yo"))])
    assert extract_response_text(obj) == "yo"
    assert extract_response_text({"choices": []}) == ""
    assert extract_response_text({"choices": [{"message": None}]}) == ""
    assert extract_response_text({"choices": [{"message": {"content": None}}]}) == ""
    assert extract_response_text(types.SimpleNamespace(choices=[types.SimpleNamespace(message=None)])) == ""
