"""1.1.1: tool annotations, the trust policy, read-context nouns and floor reasons.

Cases by origin (counts measured with this file copied onto each base):

- 1.1.1 as first written (fb5e92f) plus amendments 1-3: see the section headers.
- "guard" tests check properties the change must keep. Read guards ("stays READ_ONLY
  as on 1.1.0") pass on 1.1.0; guards that use the new annotations field cannot run
  there.
- Counts per base are recorded in the engine's docs/RFC-6200m1-CHANGES.md.
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
    # Amendment 2: "sync" joined HINT_NEVER_LOWERS, so the unknown verb here is
    # "refresh" (sync_calendar is now held; see the amendment 2 tests).
    risk = classify_tool(_tool("refresh_calendar", **READ_HINT), _trusted())
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
    ("get_schedule", "", ClearanceLevel.READ_ONLY),
    # amendment 1: the description's own "schedule" is not dropped, so this is held.
    ("get_schedule", "Get the team's schedule", ClearanceLevel.DRAFT_ONLY),
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


# amendment 1 (review r1) -------------------------------------------------------------------

# Finding 1: a noun is dropped from the name only; the description's state verbs count.
DESCRIBED_WRITES = [
    ("get_post", "Will post the draft publicly to the channel"),
    ("get_run", "run the job now"),
    ("get_email", "email the report to the customer"),
    ("fetch_message", "message all users"),
    ("get_merge", "merge the pull request into main"),
    ("check_schedule", "schedule a new meeting"),
]


@pytest.mark.parametrize("name,description", DESCRIBED_WRITES)
def test_a_write_in_the_description_is_held_even_after_a_read_verb(name, description):
    # Default policy only, so this also runs (and holds) on 1.1.0.
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.clearance is ClearanceLevel.DRAFT_ONLY, name
    assert risk.category == "state_changing"


@pytest.mark.parametrize("name,description", DESCRIBED_WRITES)
def test_a_described_write_is_held_under_a_trusting_policy_without_hints(name, description):
    risk = classify_tool(McpToolDescriptor(name=name, description=description), _trusted())
    assert risk.clearance is ClearanceLevel.DRAFT_ONLY, name


def _get_post_on_a_read_only_server():
    report = audit_tool_surface_sync(
        [McpToolDescriptor(name="get_post",
                           description="Will post the draft publicly to the channel")],
        use_overseer=False).to_dict()
    report["recommended_clearance"] = "READ_ONLY"
    return enforce_from_report(report, tool_name="get_post", execution_mode="AUTO")


def test_a_described_write_is_not_auto_approved_on_a_read_only_server():
    assert _get_post_on_a_read_only_server().status == "requires_approval"


def test_the_hold_on_a_described_write_names_the_tool_floor():
    reason = _get_post_on_a_read_only_server().reason
    assert "the tool is classified DRAFT_ONLY (state-changing verb: post)" in reason


# Finding 2: the read verb is the name's first word and the noun is its second word.
@pytest.mark.parametrize("name", ["get_schedule", "list_message_threads", "show_email",
                                  "read_post", "view_run", "describe_commit",
                                  "fetch_merge"])
def test_each_ambiguous_noun_reads_as_a_noun_right_after_a_read_verb(name):
    risk = classify_tool(McpToolDescriptor(name=name))
    assert risk.clearance is ClearanceLevel.READ_ONLY, name
    assert any(s.startswith("read context:") for s in risk.signals)


@pytest.mark.parametrize("name", [
    "status_post", "explain_commit", "list_run_via_message", "health_run",
    "summarize_email", "check_schedule", "count_run", "get_email_message_post",
    "list_all_runs_then_merge", "get_latest_post", "query_run", "preview_merge",
])
def test_the_read_context_is_only_a_listed_read_verb_then_the_noun(name):
    assert classify_tool(McpToolDescriptor(name=name)).clearance \
        is not ClearanceLevel.READ_ONLY, name


# Finding 4: contradictory hints get the stricter one.
@pytest.mark.parametrize("trusted", [False, True])
def test_destructive_and_read_only_hints_together_are_destructive(trusted):
    policy = _trusted() if trusted else None
    for name in ("sync_calendar", "noop", "get_schedule", "list_files"):
        risk = classify_tool(_tool(name, readOnlyHint=True, destructiveHint=True), policy)
        assert risk.category == "destructive", name
        assert risk.clearance is ClearanceLevel.DRAFT_ONLY


# Finding 5: a trusted readOnlyHint never lowers outbound or side-effect verbs.
@pytest.mark.parametrize("name,description", [
    ("send_email", ""), ("publish_post", ""), ("notify_team", ""), ("share_doc", ""),
    ("sync_calendar", "create an event"), ("trigger_run", ""),
])
def test_a_trusted_read_only_hint_never_lowers_an_outbound_verb(name, description):
    risk = classify_tool(_tool(name, description, **READ_HINT), _trusted())
    assert risk.clearance is not ClearanceLevel.READ_ONLY, name


# amendment 2 (review r2) -------------------------------------------------------------------

# Finding 1: the noun is dropped by position only; a later copy of it in the name counts.
REPEATED_NOUNS = ["get_post_and_post", "get_commit_to_commit", "list_message_then_message",
                  "get_email_or_email", "get_run_run", "fetch_merge_merge"]


@pytest.mark.parametrize("name", REPEATED_NOUNS)
def test_a_repeated_noun_in_the_name_is_held(name):
    risk = classify_tool(McpToolDescriptor(name=name))
    assert risk.clearance is ClearanceLevel.DRAFT_ONLY, name
    assert risk.category == "state_changing"


def test_a_repeated_noun_is_not_auto_approved_on_a_read_only_server():
    report = audit_tool_surface_sync([McpToolDescriptor(name="get_post_and_post")],
                                     use_overseer=False).to_dict()
    report["recommended_clearance"] = "READ_ONLY"
    out = enforce_from_report(report, tool_name="get_post_and_post", execution_mode="AUTO")
    assert out.status == "requires_approval"


# Finding 2: more outbound and side-effect words a trusted hint never lowers.
@pytest.mark.parametrize("name", ["message_user", "push_changes", "deploy_app", "upload_file",
                                  "grant_access", "invite_user", "approve_pr", "trigger_build",
                                  "sync_calendar", "forward_mail", "reply_thread",
                                  "export_report"])
def test_a_trusted_read_only_hint_never_lowers_a_side_effect_word(name):
    risk = classify_tool(_tool(name, **READ_HINT), _trusted())
    assert risk.clearance is not ClearanceLevel.READ_ONLY, name


# Finding 3: -s/-es verb forms of state words count (final form of amendment 2: -ed and
# -ing are not matched, so ordinary reads stay as on 1.1.0).
@pytest.mark.parametrize("name,description", [
    ("get_post", "Fetches; then posts it"),
    ("get_report", "Builds the report and posts it to the channel"),
    ("list_jobs", "Lists jobs and commits pending ones"),
    ("get_branch", "Gets the branch and pushes it"),
    ("view_pr", "Views the PR, then merges it"),
    ("show_calendar", "Shows the calendar and schedules a meeting"),
    ("get_status", "Gets status and updates the record"),
    ("view_queue", "Runs the next job"),
    ("read_inbox", "Reads mail and emails a summary"),
    ("get_draft", "Gets the draft and publishes it"),
])
def test_an_inflected_state_word_in_the_description_is_held(name, description):
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.clearance is ClearanceLevel.DRAFT_ONLY, (name, description)


@pytest.mark.parametrize("name", ["list_jobs_and_commits", "posts_list",
                                  "get_and_sends", "fetch_then_pushes", "list_or_schedules"])
def test_an_inflected_state_word_in_the_name_is_held(name):
    assert classify_tool(McpToolDescriptor(name=name)).clearance is ClearanceLevel.DRAFT_ONLY


@pytest.mark.parametrize("name,description", [
    ("list_messages", "List messages in a folder"),
    ("search_emails", "Search messages"),
    ("get_posts", "Lists posts by author"),
    ("list_runs", "Lists runs of a workflow"),
    ("get_settings", "Read settings"),
])
def test_an_inflected_noun_read_by_a_read_verb_stays_read_only(name, description):
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.clearance is ClearanceLevel.READ_ONLY, (name, description)


@pytest.mark.parametrize("name,description", [
    ("get_rows", "Fetches rows, then deletes them"),
    ("list_files", "Lists files and removes the old ones"),
    ("get_account", "Gets the account and transfers the balance"),
])
def test_a_destructive_verb_form_in_the_description_is_destructive(name, description):
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.category == "destructive", (name, description)


@pytest.mark.parametrize("name,description", [
    ("get_setting", "Read one setting"),
    ("get_status", "Get the last updated time"),
    ("list_items", "List created items"),
    ("list_jobs", "List pending jobs"),
])
def test_guard_ed_and_ing_forms_keep_an_ordinary_read_read_only(name, description):
    """As on 1.1.0 (these pass there): -ed and -ing forms are not verbs to match."""
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.clearance is ClearanceLevel.READ_ONLY, (name, description)


@pytest.mark.parametrize("name,description", [
    ("get_item_updates", ""), ("show_report_posts", ""), ("list_charges", "List charges"),
    ("get_payments", "Get payments"), ("list_refunds", "List refunds"),
    ("list_formats", "List supported formats"), ("get_runs", "Get recent runs"),
    ("get_updates", "Get latest updates"),
])
def test_guard_a_plural_noun_keeps_an_ordinary_read_read_only(name, description):
    """As on 1.1.0 (these pass there): an -s form outside a verb position is a plural."""
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.clearance is ClearanceLevel.READ_ONLY, (name, description)


@pytest.mark.parametrize("name", ["deletes_rows", "get_and_removes", "list_then_purges"])
def test_a_destructive_verb_form_in_the_name_is_destructive(name):
    assert classify_tool(McpToolDescriptor(name=name)).category == "destructive", name


# amendment 3 (review r3) -------------------------------------------------------------------

# When the read-context noun rule fires, every state or destructive word counts in any
# form and position (except a plural right after a read verb or a noun-leading word).
@pytest.mark.parametrize("name,description", [
    ("get_post", "Fetches the draft and immediately posts it"),
    ("get_post", "Fetches the draft \u2014 posts it"),
    ("get_post", "Fetches the draft\uff61 posts it"),
    ("get_run", "Returns runs and reruns them"),
    ("get_post_posts", ""),
    ("get_post_sends", ""),
    ("get_run_merges", ""),
])
def test_a_noun_rule_read_is_held_by_a_state_word_in_any_form(name, description):
    risk = classify_tool(McpToolDescriptor(name=name, description=description))
    assert risk.clearance is not ClearanceLevel.READ_ONLY, (name, description)


@pytest.mark.parametrize("name", ["get_post_thenPublish", "list_itemsThenDelete"])
def test_a_camel_case_word_in_the_name_counts(name):
    assert classify_tool(McpToolDescriptor(name=name)).clearance \
        is not ClearanceLevel.READ_ONLY, name


def test_guard_the_camel_case_split_never_lowers_a_name():
    """As on 1.1.0: a read verb inside a camelCase word is not found by the split."""
    for name in ("getUser", "listOrders", "getSchedule"):
        assert classify_tool(McpToolDescriptor(name=name)).clearance \
            is ClearanceLevel.DRAFT_ONLY, name


@pytest.mark.parametrize("mark", ["\u2014", "\u2013", "|", "/", "&", "\u3002", "\uff61", "\n"])
def test_more_marks_break_a_description_clause(mark):
    risk = classify_tool(McpToolDescriptor(name="get_report",
                                           description=f"Builds the report{mark}posts it"))
    assert risk.clearance is ClearanceLevel.DRAFT_ONLY, repr(mark)
