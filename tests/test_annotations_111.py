"""1.1.1: tool annotations, the trust policy, read-context nouns and floor reasons.

19 tests; 14 fail on 1.1.0 (36a2fd2). The 5 that pass there are the names that must
stay DRAFT_ONLY. The two tests named "guard" check properties the change must keep, but
use the new field, so they cannot run on 1.1.0.
"""
from __future__ import annotations

import pytest

from mcp_auditor import (
    AllowlistedServer,
    AllowlistPolicy,
    ClassificationPolicy,
    McpToolDescriptor,
    audit_tool_surface_sync,
    classify_tool,
    enforce_from_report,
    surface_fingerprint,
)
from mcp_auditor.fetch import serialize_tool_list
from mcp_auditor.types import ClearanceLevel



def _trusted():
    return ClassificationPolicy(trust_annotations=True)

READ_HINT = {"readOnlyHint": True}


def _tool(name, description="", **annotations):
    return McpToolDescriptor(name=name, description=description, annotations=annotations)


# (a) the descriptor carries annotations ------------------------------------------------

def test_the_descriptor_keeps_boolean_hints_from_a_listing():
    tools = serialize_tool_list({"tools": [{"name": "sync_calendar", "annotations": {
        "readOnlyHint": True, "destructiveHint": "yes", "title": "x"}}]})
    assert tools[0].annotations == {"readOnlyHint": True}
    assert McpToolDescriptor.from_dict(tools[0].to_dict()).annotations == {"readOnlyHint": True}


def test_guard_a_descriptor_without_annotations_serialises_as_in_1_1_0():
    assert "annotations" not in McpToolDescriptor(name="get_x").to_dict()
    assert surface_fingerprint([McpToolDescriptor(name="get_x")]) == \
        surface_fingerprint([McpToolDescriptor(name="get_x", annotations={})])


def test_a_change_to_annotations_is_surface_drift():
    assert surface_fingerprint([_tool("sync_calendar")]) != \
        surface_fingerprint([_tool("sync_calendar", **READ_HINT)])


# (b) annotations narrow risk only for a trusted server -----------------------------------

def test_a_trusted_servers_read_only_hint_lowers_an_unknown_verb_to_read_only():
    risk = classify_tool(_tool("sync_calendar", **READ_HINT), _trusted())
    assert risk.clearance is ClearanceLevel.READ_ONLY
    assert "trusted" in risk.signals[0]


def test_an_untrusted_server_cannot_talk_its_way_into_read_only():
    for tool in (_tool("sync_calendar", **READ_HINT),
                 _tool("update_record", **READ_HINT)):
        assert classify_tool(tool).clearance is ClearanceLevel.DRAFT_ONLY, tool.name


def test_guard_even_trusted_hints_never_lower_a_destructive_verb_or_a_non_ascii_name():
    assert classify_tool(_tool("delete_rows", **READ_HINT), _trusted()).category == "destructive"
    assert classify_tool(_tool("dеlete_rows", **READ_HINT), _trusted()).clearance \
        is ClearanceLevel.DRAFT_ONLY                       # Cyrillic "е"
    both = _tool("sync_calendar", readOnlyHint=True, destructiveHint=True)
    assert classify_tool(both, _trusted()).clearance is ClearanceLevel.DRAFT_ONLY


def test_a_destructive_hint_always_makes_a_tool_stricter():
    risk = classify_tool(_tool("list_files", destructiveHint=True))
    assert risk.category == "destructive" and risk.clearance is ClearanceLevel.DRAFT_ONLY


def test_trust_survives_with_extra():
    assert _trusted().with_extra(read_only=["peek"]).trust_annotations is True


# (c) 'schedule' after a read verb is a noun ------------------------------------------------

@pytest.mark.parametrize("name,description,expected", [
    ("get_schedule", "Get the team's schedule", ClearanceLevel.READ_ONLY),
    ("list_schedule_entries", "", ClearanceLevel.READ_ONLY),
    ("read_schedule", "", ClearanceLevel.READ_ONLY),
    ("schedule_meeting", "Schedule a meeting", ClearanceLevel.DRAFT_ONLY),
    ("get_and_schedule", "", ClearanceLevel.DRAFT_ONLY),
    ("get_or_run_job", "", ClearanceLevel.DRAFT_ONLY),
    ("get_schedule", "Get the schedule and create an event", ClearanceLevel.DRAFT_ONLY),
    ("schedule", "Get the schedule", ClearanceLevel.DRAFT_ONLY),
])
def test_schedule_in_a_read_verb_context_is_not_a_state_change(name, description, expected):
    assert classify_tool(McpToolDescriptor(name=name, description=description)).clearance \
        is expected


# (d) a held call names its floor -----------------------------------------------------------

def test_a_read_tool_held_by_its_servers_floor_says_so():
    report = audit_tool_surface_sync([McpToolDescriptor(name="get_schedule")],
                                     use_overseer=False).to_dict()
    assert report["tools"][0]["clearance"] == "READ_ONLY"
    out = enforce_from_report(report, tool_name="get_schedule", execution_mode="AUTO")
    assert out.status == "requires_approval"
    assert "the server's clearance is DRAFT_ONLY" in out.reason
    assert "SKIPPED" in out.reason and "mutating" not in out.reason
    assert "the tool is classified" not in out.reason


def test_a_mutating_tool_held_by_its_classification_says_so():
    report = audit_tool_surface_sync([McpToolDescriptor(name="schedule_meeting")],
                                     use_overseer=False).to_dict()
    report["recommended_clearance"] = "READ_ONLY"
    out = enforce_from_report(report, tool_name="schedule_meeting", execution_mode="AUTO")
    assert "the tool is classified DRAFT_ONLY (state-changing verb: schedule)" in out.reason
    assert "requires human approval" in out.reason


def test_a_server_without_an_audit_names_its_set_clearance():
    pol = AllowlistPolicy(enabled=True)
    pol.upsert(AllowlistedServer(server_id="cal"))
    out = pol.evaluate(server_id="cal", tool_name="get_schedule", execution_mode="AUTO")
    assert out.status == "requires_approval" and "no audit report" in out.reason
