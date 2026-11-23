"""Core package tests (no host application imports)."""
from __future__ import annotations

import pytest

from mcp_auditor import (
    AllowlistPolicy,
    AllowlistedServer,
    ClearanceLevel,
    McpToolDescriptor,
    audit_tool_surface,
    audit_tool_surface_sync,
    classify_tool,
    detect_drift,
    enforce_from_report,
    enforce_tool_call,
    max_clearance,
    surface_fingerprint,
)


def test_classify_and_max():
    assert classify_tool(McpToolDescriptor(name="list_orders")).clearance is ClearanceLevel.READ_ONLY
    assert classify_tool(McpToolDescriptor(name="create_invoice")).clearance is ClearanceLevel.DRAFT_ONLY
    assert classify_tool(McpToolDescriptor(name="delete_customer")).category == "destructive"
    assert max_clearance(ClearanceLevel.READ_ONLY, ClearanceLevel.BLOCKED) is ClearanceLevel.BLOCKED
    # Unknown verbs fail closed (never silent READ_ONLY).
    unknown = classify_tool(McpToolDescriptor(name="customer_sync"))
    assert unknown.clearance is ClearanceLevel.DRAFT_ONLY
    assert unknown.category == "state_changing"


def test_fingerprint_stable():
    tools = [McpToolDescriptor(name="a"), McpToolDescriptor(name="b", description="x")]
    assert surface_fingerprint(tools) == surface_fingerprint(list(reversed(tools)))


@pytest.mark.asyncio
async def test_audit_static_and_overseer_fail_closed():
    tools = [McpToolDescriptor(name="get_x")]
    # Overseer-off / SKIPPED must floor to DRAFT_ONLY (never open auto-execute).
    report = await audit_tool_surface(tools, use_overseer=False)
    assert report.overseer_verdict == "SKIPPED"
    assert report.recommended_clearance is ClearanceLevel.DRAFT_ONLY
    assert report.static_clearance is ClearanceLevel.READ_ONLY
    assert report.surface_fingerprint

    async def boom(_):
        raise RuntimeError("down")

    report2 = await audit_tool_surface(tools, overseer=boom, use_overseer=True)
    assert report2.overseer_verdict == "UNAVAILABLE"
    assert report2.recommended_clearance is ClearanceLevel.DRAFT_ONLY


@pytest.mark.asyncio
async def test_overseer_off_not_more_open_than_overseer_failure():
    """Failure mode: UI overseer-off must not grant READ_ONLY when failure would not."""
    tools = [McpToolDescriptor(name="list_orders"), McpToolDescriptor(name="get_record")]
    skipped = await audit_tool_surface(tools, use_overseer=False)
    assert skipped.recommended_clearance is ClearanceLevel.DRAFT_ONLY

    async def boom(_):
        raise RuntimeError("offline")

    failed = await audit_tool_surface(tools, overseer=boom, use_overseer=True)
    assert failed.recommended_clearance is ClearanceLevel.DRAFT_ONLY
    assert skipped.recommended_clearance == failed.recommended_clearance


def test_allowlist_fail_closed():
    pol = AllowlistPolicy(enabled=False)
    d = pol.evaluate(server_id="x", tool_name="t", execution_mode="AUTO")
    assert d.status == "blocked"

    pol.enabled = True
    d2 = pol.evaluate(server_id="missing", tool_name="t", execution_mode="AUTO")
    assert d2.status == "blocked"

    report = audit_tool_surface_sync(
        [McpToolDescriptor(name="get_x"), McpToolDescriptor(name="delete_x")]
    )
    pol.upsert(AllowlistedServer(
        server_id="s1",
        clearance=report.recommended_clearance,
        audit_report=report.to_dict(),
        allowed_tools=["get_x"],
    ))
    assert pol.evaluate(server_id="s1", tool_name="get_x", execution_mode="AUTO").status in {
        "auto_approved", "requires_approval"
    }
    assert pol.evaluate(server_id="s1", tool_name="delete_x", execution_mode="AUTO").status == "blocked"


def test_drift_and_enforce():
    tools = [McpToolDescriptor(name="get_x")]
    report = audit_tool_surface_sync(tools)
    drift = detect_drift(report, tools)
    assert drift.ok
    drift2 = detect_drift(report, [McpToolDescriptor(name="get_x"), McpToolDescriptor(name="evil")])
    assert not drift2.ok
    assert "evil" in drift2.added

    d = enforce_tool_call(
        server_clearance=ClearanceLevel.BLOCKED,
        tool_clearance=ClearanceLevel.READ_ONLY,
        tool_name="x",
        execution_mode="AUTO",
    )
    assert d.status == "blocked"
    d2 = enforce_from_report(
        {"recommended_clearance": "READ_ONLY", "tools": [{"name": "a", "clearance": "READ_ONLY"}]},
        tool_name="surprise",
        execution_mode="AUTO",
    )
    assert d2.status == "requires_approval"
