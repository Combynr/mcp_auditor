"""enforce_tool_call / enforce_from_report and the clearance helpers."""
from __future__ import annotations

import pytest

from mcp_auditor import (
    ClearanceLevel,
    coerce_clearance,
    enforce_from_report,
    enforce_tool_call,
    max_clearance,
)

R, D, B = ClearanceLevel.READ_ONLY, ClearanceLevel.DRAFT_ONLY, ClearanceLevel.BLOCKED


@pytest.mark.parametrize(
    "server, tool, mode, status",
    [
        (R, R, "AUTO", "auto_approved"),
        (R, R, " auto ", "auto_approved"),
        (R, R, "ASK", "requires_approval"),
        (R, R, "", "requires_approval"),
        (R, R, None, "requires_approval"),
        (R, D, "AUTO", "requires_approval"),
        (D, R, "AUTO", "requires_approval"),
        (R, B, "AUTO", "blocked"),
        (B, R, "AUTO", "blocked"),
        (B, B, "ASK", "blocked"),
    ],
)
def test_enforce_tool_call_matrix(server, tool, mode, status):
    d = enforce_tool_call(
        server_clearance=server, tool_clearance=tool, tool_name="t",
        execution_mode=mode, server_id="s",
    )
    assert d.status == status
    assert d.to_dict()["server_id"] == "s"


@pytest.mark.parametrize("raw", ["BLOCKED", "blocked", " Blocked "])
def test_string_blocked_is_never_auto_approved(raw):
    """Bug: a plain string "BLOCKED" fell through every identity check to auto_approved."""
    d = enforce_tool_call(
        server_clearance=raw, tool_clearance=raw, tool_name="t", execution_mode="AUTO"
    )
    assert d.status == "blocked"


@pytest.mark.parametrize("raw", ["", "nonsense", None, 3])
def test_unknown_clearance_values_require_approval(raw):
    d = enforce_tool_call(
        server_clearance=raw, tool_clearance=raw, tool_name="t", execution_mode="AUTO"
    )
    assert d.status == "requires_approval"


def test_coerce_clearance_keeps_enum_members():
    """Bug: str() of the enum member is "ClearanceLevel.BLOCKED", which coerced to DRAFT_ONLY."""
    assert coerce_clearance(B) is B
    assert coerce_clearance(R) is R
    assert coerce_clearance("read_only") is R
    assert coerce_clearance(None) is D
    assert coerce_clearance(object()) is D


def test_max_clearance():
    assert max_clearance() is D
    assert max_clearance(R) is R
    assert max_clearance(R, D) is D
    assert max_clearance(R, "BLOCKED") is B
    assert max_clearance(R, "garbage") is D


def _report(**kw):
    base = {
        "recommended_clearance": "READ_ONLY",
        "surface_fingerprint": "fp1",
        "tools": [{"name": "get_x", "clearance": "READ_ONLY"}],
    }
    base.update(kw)
    return base


def test_enforce_from_report_main_path():
    assert enforce_from_report(_report(), tool_name="get_x", execution_mode="AUTO").status == "auto_approved"


def test_enforce_from_report_with_enum_values_blocks():
    report = {"recommended_clearance": B, "tools": [{"name": "x", "clearance": B}]}
    assert enforce_from_report(report, tool_name="x", execution_mode="AUTO").status == "blocked"


def test_unknown_tool_requires_approval():
    assert enforce_from_report(_report(), tool_name="get_y", execution_mode="AUTO").status == "requires_approval"


@pytest.mark.parametrize("name", ["GET_X", "get_x ", "get_х"])  # case, space, Cyrillic х
def test_lookalike_tool_names_are_not_the_audited_tool(name):
    assert enforce_from_report(_report(), tool_name=name, execution_mode="AUTO").status == "requires_approval"


@pytest.mark.parametrize("name", ["", "   ", None, 7])
def test_missing_tool_name_is_blocked(name):
    report = _report(tools=[{"name": "", "clearance": "READ_ONLY"}])
    assert enforce_from_report(report, tool_name=name, execution_mode="AUTO").status == "blocked"


def test_duplicate_tool_names_take_the_strictest_entry():
    report = _report(tools=[
        {"name": "get_x", "clearance": "READ_ONLY"},
        {"name": "get_x", "clearance": "BLOCKED"},
    ])
    assert enforce_from_report(report, tool_name="get_x", execution_mode="AUTO").status == "blocked"


def test_per_tool_grant():
    assert enforce_from_report(_report(), tool_name="get_x", execution_mode="AUTO",
                               allowed_tools=["get_x"]).status == "auto_approved"
    assert enforce_from_report(_report(), tool_name="get_x", execution_mode="AUTO",
                               allowed_tools=[]).status == "blocked"


def test_bare_string_grant_is_not_a_set_of_characters():
    report = _report(tools=[{"name": "x", "clearance": "READ_ONLY"}])
    d = enforce_from_report(report, tool_name="x", execution_mode="AUTO", allowed_tools="get_x")
    assert d.status == "blocked"


def test_live_fingerprint_mismatch_blocks_even_a_granted_tool():
    ok = enforce_from_report(_report(), tool_name="get_x", execution_mode="AUTO",
                             allowed_tools=["get_x"], live_fingerprint="fp1")
    assert ok.status == "auto_approved"
    drifted = enforce_from_report(_report(), tool_name="get_x", execution_mode="AUTO",
                                  allowed_tools=["get_x"], live_fingerprint="fp2")
    assert drifted.status == "blocked"
    no_fp = enforce_from_report(_report(surface_fingerprint=""), tool_name="get_x",
                                execution_mode="AUTO", live_fingerprint="fp1")
    assert no_fp.status == "blocked"


def test_malformed_reports_fail_closed():
    assert enforce_from_report({}, tool_name="x", execution_mode="AUTO").status == "requires_approval"
    assert enforce_from_report(None, tool_name="x", execution_mode="AUTO").status == "requires_approval"
    weird = {"recommended_clearance": "READ_ONLY", "tools": ["x", None, {"name": "x"}]}
    # The entry without a clearance coerces to DRAFT_ONLY.
    assert enforce_from_report(weird, tool_name="x", execution_mode="AUTO").status == "requires_approval"
