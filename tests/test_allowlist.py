"""AllowlistPolicy / AllowlistedServer."""
from __future__ import annotations

import pytest

from mcp_auditor import (
    AllowlistedServer,
    AllowlistPolicy,
    ClearanceLevel,
    McpToolDescriptor,
    audit_tool_surface_sync,
    surface_fingerprint,
)

TOOLS = [McpToolDescriptor(name="get_x"), McpToolDescriptor(name="delete_x")]


def _safe(_tools):
    return "SAFE", "ok"


def _policy(clearance=ClearanceLevel.READ_ONLY, tools=TOOLS, **kw) -> AllowlistPolicy:
    report = audit_tool_surface_sync(tools)
    policy = AllowlistPolicy(enabled=True)
    policy.upsert(AllowlistedServer(
        server_id="s1", clearance=clearance, audit_report=report.to_dict(), **kw
    ))
    return policy


def test_main_path_with_human_override_to_read_only():
    policy = _policy()
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "auto_approved"
    assert policy.evaluate(server_id="s1", tool_name="get_x", execution_mode="ASK").status == "requires_approval"
    assert policy.evaluate(server_id="s1", tool_name="delete_x").status == "requires_approval"


def test_static_only_audit_never_auto_approves():
    report = audit_tool_surface_sync([McpToolDescriptor(name="get_x")])
    policy = AllowlistPolicy(enabled=True)
    policy.upsert(AllowlistedServer(
        server_id="s1", clearance=report.recommended_clearance, audit_report=report.to_dict()
    ))
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "requires_approval"


def test_disabled_policy_blocks_everything():
    policy = _policy()
    policy.enabled = False
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "blocked"
    assert AllowlistPolicy().evaluate(server_id="s1", tool_name="get_x").status == "blocked"


@pytest.mark.parametrize("value", ["false", "False", "no", "0", "", None, 1, "maybe"])
def test_persisted_enabled_flag_only_opens_on_an_explicit_yes(value):
    """Bug: bool("false") is True, so a string "false" switched the master gate on."""
    data = _policy().to_dict()
    data["enabled"] = value
    policy = AllowlistPolicy.from_dict(data)
    assert policy.enabled is False
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "blocked"


@pytest.mark.parametrize("value", [True, "true", "YES", "on", "1"])
def test_persisted_enabled_flag_yes_values(value):
    data = _policy().to_dict()
    data["enabled"] = value
    assert AllowlistPolicy.from_dict(data).enabled is True


def test_enabled_attribute_must_be_true_not_truthy():
    policy = _policy()
    policy.enabled = "false"  # type: ignore[assignment]
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "blocked"


@pytest.mark.parametrize("sid", ["", "   ", None, "missing", "S1"])
def test_unknown_or_missing_server_is_blocked(sid):
    assert _policy().evaluate(server_id=sid, tool_name="get_x").status == "blocked"


def test_revoked_server_is_blocked():
    policy = _policy()
    assert policy.revoke("s1") is True
    assert policy.revoke("nope") is False
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "blocked"


def test_unknown_status_is_blocked():
    policy = _policy()
    policy.servers["s1"].status = "Active "
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "blocked"


def test_tool_missing_from_audit_requires_approval():
    assert _policy().evaluate(server_id="s1", tool_name="drop_db").status == "requires_approval"


def test_empty_audited_surface_does_not_open_every_tool():
    """Bug: a report with zero tools fell back to server clearance, auto-approving any name."""
    policy = _policy(tools=[])
    assert policy.evaluate(server_id="s1", tool_name="delete_everything").status == "requires_approval"


@pytest.mark.parametrize("name", ["", None])
def test_blank_tool_name_is_blocked(name):
    assert _policy().evaluate(server_id="s1", tool_name=name).status == "blocked"
    no_report = AllowlistPolicy(enabled=True)
    no_report.upsert(AllowlistedServer(server_id="s1", clearance=ClearanceLevel.READ_ONLY))
    assert no_report.evaluate(server_id="s1", tool_name=name).status == "blocked"


def test_per_tool_grant_blocks_other_tools():
    policy = _policy(allowed_tools=["get_x"])
    assert policy.evaluate(server_id="s1", tool_name="get_x").status == "auto_approved"
    assert policy.evaluate(server_id="s1", tool_name="delete_x").status == "blocked"
    assert policy.evaluate(server_id="s1", tool_name="GET_X").status == "blocked"


def test_server_without_audit_report_uses_server_clearance_and_grant():
    policy = AllowlistPolicy(enabled=True)
    policy.upsert(AllowlistedServer(server_id="s1", allowed_tools=["a"]))
    assert policy.evaluate(server_id="s1", tool_name="a").status == "requires_approval"
    assert policy.evaluate(server_id="s1", tool_name="b").status == "blocked"


def test_grant_does_not_outlive_a_surface_change():
    policy = _policy(allowed_tools=["get_x"])
    audited = surface_fingerprint(TOOLS)
    assert policy.evaluate(server_id="s1", tool_name="get_x",
                           live_fingerprint=audited).status == "auto_approved"
    changed = [McpToolDescriptor(name="get_x", description="also deletes everything"),
               McpToolDescriptor(name="delete_x")]
    d = policy.evaluate(server_id="s1", tool_name="get_x",
                        live_fingerprint=surface_fingerprint(changed))
    assert d.status == "blocked"
    assert "re-audit" in d.reason


def test_live_fingerprint_without_audit_on_file_blocks():
    policy = AllowlistPolicy(enabled=True)
    policy.upsert(AllowlistedServer(server_id="s1", clearance=ClearanceLevel.READ_ONLY))
    assert policy.evaluate(server_id="s1", tool_name="a", live_fingerprint="x").status == "blocked"


def test_string_clearance_on_server_entry_is_coerced():
    srv = AllowlistedServer(server_id="s1", clearance="BLOCKED")  # type: ignore[arg-type]
    assert srv.clearance is ClearanceLevel.BLOCKED
    policy = AllowlistPolicy(enabled=True)
    policy.upsert(srv)
    assert policy.evaluate(server_id="s1", tool_name="a").status == "blocked"


def test_round_trip_and_malformed_grants():
    policy = _policy(allowed_tools=["get_x"])
    again = AllowlistPolicy.from_dict(policy.to_dict())
    assert again.to_dict() == policy.to_dict()
    assert again.evaluate(server_id="s1", tool_name="get_x").status == "auto_approved"

    data = policy.to_dict()
    data["servers"]["s1"]["allowed_tools"] = "get_x"  # malformed: not a list
    broken = AllowlistPolicy.from_dict(data)
    assert broken.servers["s1"].allowed_tools == []
    assert broken.evaluate(server_id="s1", tool_name="g").status == "blocked"


def test_from_dict_fills_server_id_from_key_and_defaults_closed():
    policy = AllowlistPolicy.from_dict({"enabled": True, "servers": {"k": {"clearance": "nope"}}})
    assert policy.servers["k"].clearance is ClearanceLevel.DRAFT_ONLY
    assert AllowlistPolicy.from_dict(None).enabled is False
