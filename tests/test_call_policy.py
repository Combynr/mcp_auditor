"""1.1: caller capabilities, tenant, agent tool list and declared argument rules."""
from __future__ import annotations

import os

import pytest

from mcp_auditor import (
    AllowlistedServer,
    AllowlistPolicy,
    ArgumentPolicy,
    ArgumentRule,
    CallContext,
    ClearanceLevel,
    ToolArgumentSchema,
    detect_families,
    enforce_from_report,
    validate_arguments,
)

R, D, B = ClearanceLevel.READ_ONLY, ClearanceLevel.DRAFT_ONLY, ClearanceLevel.BLOCKED
BOTH = frozenset({"mcp:read", "mcp:write"})


def _report(*tools: tuple[str, ClearanceLevel], server: ClearanceLevel = R, desc: str = "") -> dict:
    return {
        "recommended_clearance": server.value,
        "tools": [{"name": n, "clearance": c.value, "description": desc} for n, c in tools],
    }


def _write_file_schema(**extra) -> ToolArgumentSchema:
    return ToolArgumentSchema(
        tool="write_file",
        family="file_write",
        arguments={
            "path": ArgumentRule(type="string", required=True, format="path"),
            "content": ArgumentRule(type="string", required=True, max_bytes=64),
        },
        **extra,
    )


def _call(tool: str, args, *, report=None, policy=None, context=None, mode="AUTO", **kw):
    return enforce_from_report(
        report if report is not None else _report((tool, R)),
        tool_name=tool, execution_mode=mode, server_id="srv", arguments=args,
        argument_policy=policy, context=context, **kw,
    )


# -- strict types, floors and caps --------------------------------------------------

LIMIT = ToolArgumentSchema(tool="list_rows", arguments={
    "limit": ArgumentRule(type="integer", minimum=1, maximum=2500),
    "ratio": ArgumentRule(type="number", minimum=0, maximum=1),
    "dry_run": ArgumentRule(type="boolean"),
    "mode": ArgumentRule(type="string", enum=("fast", "safe")),
})


@pytest.mark.parametrize("args, ok", [
    ({"limit": 2499}, True),
    ({"limit": "2499"}, False),          # a numeric string is not an integer
    ({"limit": True}, False),            # bool is not an integer
    ({"limit": 2499.0}, False),          # nor is a float
    ({"limit": 0}, False),               # floor
    ({"limit": 2501}, False),            # cap
    ({"ratio": 0.5}, True),
    ({"ratio": True}, False),
    ({"ratio": float("nan")}, False),
    ({"ratio": 1.5}, False),
    ({"dry_run": 1}, False),
    ({"dry_run": False}, True),
    ({"mode": "fast"}, True),
    ({"mode": "FAST"}, False),
    ({"other": 1}, False),               # undeclared argument
])
def test_strict_types_floors_and_caps(args, ok):
    assert (validate_arguments(LIMIT, args) == []) is ok
    d = _call("list_rows", args, policy=ArgumentPolicy(schemas=(LIMIT,)))
    assert d.status == ("auto_approved" if ok else "blocked")
    if not ok:
        assert "list_rows" in d.reason and "declared rules" in d.reason


def test_required_argument_and_enum_of_bool_vs_int():
    schema = ToolArgumentSchema(tool="t", arguments={
        "a": ArgumentRule(type="integer", required=True, enum=(1,))})
    assert validate_arguments(schema, {}) == ["argument 'a' is required"]
    assert validate_arguments(schema, {"a": 1}) == []
    assert validate_arguments(schema, {"a": True})  # True == 1 must not pass


# -- paths ---------------------------------------------------------------------------

def test_paths_must_stay_inside_the_workspace_root(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (tmp_path / "outside").mkdir()
    policy = ArgumentPolicy(schemas=(_write_file_schema(),), workspace_root=str(root))
    report = _report(("write_file", D), server=D)
    ok = _call("write_file", {"path": "notes/a.txt", "content": "x"}, report=report, policy=policy)
    assert ok.status == "requires_approval"
    for bad in ("../outside/a.txt", str(tmp_path / "outside" / "a.txt"), "a\x00b", "",
                "notes/../../outside/x"):
        d = _call("write_file", {"path": bad, "content": "x"}, report=report, policy=policy,
                  mode="HITL")
        assert d.status == "blocked", bad
        assert "path" in d.reason


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_a_symlink_out_of_the_root_is_refused(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    try:
        os.symlink(tmp_path, root / "escape")
    except OSError:
        pytest.skip("symlinks not permitted")
    policy = ArgumentPolicy(schemas=(_write_file_schema(),), workspace_root=str(root))
    d = _call("write_file", {"path": "escape/x", "content": "x"}, policy=policy)
    assert d.status == "blocked" and "outside the workspace root" in d.reason


def test_a_path_rule_without_a_root_refuses():
    d = _call("write_file", {"path": "a.txt", "content": "x"},
              policy=ArgumentPolicy(schemas=(_write_file_schema(),)))
    assert d.status == "blocked" and "no workspace root" in d.reason


def test_the_context_root_overrides_the_policy_root(tmp_path):
    policy = ArgumentPolicy(schemas=(_write_file_schema(),), workspace_root="/nonexistent-root")
    d = _call("write_file", {"path": "a.txt", "content": "x"}, policy=policy,
              context=CallContext(workspace_root=str(tmp_path)))
    assert d.status == "auto_approved"


# -- recipients, domains, URLs, sizes -----------------------------------------------

MAIL = ToolArgumentSchema(tool="send_email", family="email", arguments={
    "to": ArgumentRule(type="array", required=True, max_items=3, items=ArgumentRule(
        type="string", format="email", allowed_domains=("example.com", "*.example.org"),
        allowed_recipients=("partner@vendor.test",))),
    "body": ArgumentRule(type="string", max_bytes=20),
})


@pytest.mark.parametrize("to, ok", [
    (["a@example.com"], True),
    (["A@Example.COM"], True),
    (["x@team.example.org"], True),
    (["x@example.org"], False),                 # *.example.org is subdomains only
    (["partner@vendor.test"], True),
    (["other@vendor.test"], False),
    (["a@example.com.evil.test"], False),
    (["a@example.com, b@evil.test"], False),    # one address per item
    (["Name <a@example.com>"], False),
    (["a@example.com\r\nBcc: b@evil.test"], False),
    (["a@example.com"] * 4, False),             # row limit
    ("a@example.com", False),                   # not an array
])
def test_recipient_allowlist(to, ok):
    assert (validate_arguments(MAIL, {"to": to}) == []) is ok


def test_byte_limit_counts_utf8_bytes():
    assert validate_arguments(MAIL, {"to": ["a@example.com"], "body": "é" * 10}) == []
    assert validate_arguments(MAIL, {"to": ["a@example.com"], "body": "é" * 11})


def test_an_email_rule_with_no_allowlist_refuses():
    schema = ToolArgumentSchema(tool="m", arguments={"to": ArgumentRule(type="string",
                                                                         format="email")})
    assert "no recipient or domain allowlist" in validate_arguments(schema, {"to": "a@b.test"})[0]


HTTP = ToolArgumentSchema(tool="http_post", family="http", max_total_bytes=200, arguments={
    "url": ArgumentRule(type="string", required=True, format="url",
                        allowed_domains=("api.example.com",)),
    "payload": ArgumentRule(type="object", max_items=5),
})


@pytest.mark.parametrize("url, ok", [
    ("https://api.example.com/v1/x", True),
    ("http://api.example.com/v1/x", False),
    ("https://user:pw@api.example.com/", False),
    ("https://api.example.com.evil.test/", False),
    ("https://evil.test/?u=https://api.example.com", False),
    ("file:///etc/passwd", False),
    ("not a url", False),
])
def test_url_domain_allowlist(url, ok):
    assert (validate_arguments(HTTP, {"url": url}) == []) is ok


def test_total_and_item_limits():
    assert validate_arguments(HTTP, {"url": "https://api.example.com/",
                                     "payload": {str(i): i for i in range(6)}})
    assert validate_arguments(HTTP, {"url": "https://api.example.com/", "payload": {"x": "y" * 300}})


# -- renamed tools -------------------------------------------------------------------

def test_a_renamed_write_tool_still_matches_the_declared_schema(tmp_path):
    """``save_note`` is ``write_file`` under another name: its rules still bind it."""
    policy = ArgumentPolicy(schemas=(_write_file_schema(),), workspace_root=str(tmp_path))
    report = _report(("save_note", R))  # the classifier was fooled: READ_ONLY
    escape = _call("save_note", {"path": "../../etc/x", "content": "x"}, report=report,
                   policy=policy)
    assert escape.status == "blocked" and "outside the workspace root" in escape.reason
    inside = _call("save_note", {"path": "a.txt", "content": "x"}, report=report, policy=policy)
    assert inside.status == "requires_approval"  # renamed: never auto-approved
    assert "no declared argument schema" in inside.reason


def test_an_undeclared_shell_tool_with_a_bland_name_is_held():
    """The 1.0 limitation: ``get_report`` hiding a shell. With a policy it is held."""
    report = _report(("get_report", R), desc="Returns the report")
    args = {"command": "rm -rf /"}
    assert _call("get_report", args, report=report).status == "auto_approved"  # 1.0 path
    held = _call("get_report", args, report=report, policy=ArgumentPolicy())
    assert held.status == "requires_approval"
    assert "shell" in held.reason


@pytest.mark.parametrize("name, desc, args, family", [
    ("writeFile", "", {}, "file_write"),
    ("put_object", "", {"path": "a", "data": "b"}, "file_write"),
    ("run_it", "", {"cmd": "ls"}, "shell"),
    ("notify", "", {"recipients": ["a@b.test"]}, "email"),
    ("lookup", "", {"webhook_url": "https://x"}, "http"),
    ("lookup", "", {"nested": {"url": "https://x"}}, "http"),
    ("update_range", "Write values to an Excel worksheet", {}, "office_write"),
])
def test_family_detection_looks_past_the_name(name, desc, args, family):
    assert family in detect_families(name, desc, args)


@pytest.mark.parametrize("name", ["list_issues", "get_user", "fetch_issues", "list_pull_requests",
                                  "search_docs", "read_file"])
def test_ordinary_reads_are_not_high_risk(name):
    assert detect_families(name, "", {"query": "x", "path": "a.txt"}) == frozenset()


def test_an_alias_is_the_declared_tool(tmp_path):
    policy = ArgumentPolicy(schemas=(_write_file_schema(aliases=("fs_write",)),),
                            workspace_root=str(tmp_path))
    d = _call("fs_write", {"path": "a.txt", "content": "x"}, policy=policy)
    assert d.status == "auto_approved"
    assert _call("fs_write", {"path": "../a", "content": "x"}, policy=policy).status == "blocked"


def test_declared_tool_without_arguments_is_held_not_auto_approved(tmp_path):
    policy = ArgumentPolicy(schemas=(LIMIT,))
    assert _call("list_rows", None, policy=policy).status == "requires_approval"


def test_violations_block_even_in_approval_mode():
    d = _call("list_rows", {"limit": "9"}, policy=ArgumentPolicy(schemas=(LIMIT,)), mode="HITL")
    assert d.status == "blocked"


# -- caller role, tenant, agent profile ----------------------------------------------

def test_capabilities_intersect_with_clearance():
    reader = CallContext(capabilities=frozenset({"mcp:read"}))
    assert _call("get_x", {}, context=reader).status == "auto_approved"
    report = _report(("create_x", D), server=D)
    d = _call("create_x", {}, report=report, context=reader, mode="HITL")
    assert d.status == "blocked" and "mcp:write" in d.reason
    assert _call("create_x", {}, report=report, context=CallContext(capabilities=BOTH),
                 mode="HITL").status == "requires_approval"
    nobody = CallContext(capabilities=frozenset())
    assert _call("get_x", {}, context=nobody).status == "blocked"


def test_a_schema_capability_is_also_required():
    schema = ToolArgumentSchema(tool="get_x", capability="mcp:payments", allow_additional=True)
    policy = ArgumentPolicy(schemas=(schema,))
    d = _call("get_x", {}, policy=policy, context=CallContext(capabilities=BOTH))
    assert d.status == "blocked" and "mcp:payments" in d.reason
    ok = CallContext(capabilities=BOTH | {"mcp:payments"})
    assert _call("get_x", {}, policy=policy, context=ok).status == "auto_approved"


def test_tenant_must_match_the_server():
    d = _call("get_x", {}, context=CallContext(tenant_id="t2"), server_tenant_id="t1")
    assert d.status == "blocked" and "tenant" in d.reason
    assert _call("get_x", {}, server_tenant_id="t1").status == "blocked"  # no caller tenant
    assert _call("get_x", {}, context=CallContext(tenant_id="t1"),
                 server_tenant_id="t1").status == "auto_approved"


@pytest.mark.parametrize("tools, ok", [
    (["get_x"], True), (["srv:get_x"], True), (["srv:*"], True),
    (["other:get_x"], False), ([], False), ("get_x", False),
])
def test_agent_profile_tool_list(tools, ok):
    d = _call("get_x", {}, context=CallContext(agent_tools=tools))
    assert d.status == ("auto_approved" if ok else "blocked")
    if not ok:
        assert "agent profile" in d.reason


# -- persistence and the 1.0 API -------------------------------------------------------

def test_policy_round_trips_and_1_0_entries_serialise_unchanged(tmp_path):
    policy = ArgumentPolicy(schemas=(_write_file_schema(), MAIL, HTTP, LIMIT),
                            workspace_root=str(tmp_path))
    again = ArgumentPolicy.from_dict(policy.to_dict())
    assert again.to_dict() == policy.to_dict()
    assert set(AllowlistedServer(server_id="s").to_dict()) == {
        "server_id", "display_name", "status", "clearance", "recommended_clearance",
        "audit_report", "allowed_tools", "transport", "endpoint", "note"}


@pytest.mark.parametrize("bad", [
    {"schemas": [{"tool": "list_rows", "arguments": {"limit": {"type": "int"}}}]},
    {"schemas": [{"tool": "list_rows", "arguments": {"limit": {"type": "integer",
                                                                "maximum": "10"}}}]},
    {"schemas": [{"tool": "list_rows", "arguments": "limit"}]},
    {"schemas": [{"tool": "list_rows", "arguments": {"limit": {"type": "integer"}},
                  "max_total_bytes": "1"}]},
])
def test_a_malformed_stored_rule_refuses(bad):
    d = _call("list_rows", {"limit": 5}, report={**_report(("list_rows", R)),
                                                 "argument_policy": bad})
    assert d.status == "blocked"


def test_allowlist_policy_applies_stored_rules_and_tenant(tmp_path):
    srv = AllowlistedServer(
        server_id="fs", clearance=R, tenant_id="acme",
        audit_report=_report(("write_file", R)),
        argument_policy=ArgumentPolicy(schemas=(_write_file_schema(),),
                                       workspace_root=str(tmp_path)).to_dict(),
    )
    policy = AllowlistPolicy.from_dict(AllowlistPolicy(enabled=True, servers={"fs": srv}).to_dict())
    ctx = CallContext(tenant_id="acme", capabilities=BOTH, agent_tools=["fs:*"])
    ok = policy.evaluate(server_id="fs", tool_name="write_file", context=ctx,
                         arguments={"path": "a.txt", "content": "x"})
    assert ok.status == "auto_approved"
    bad = policy.evaluate(server_id="fs", tool_name="write_file", context=ctx,
                          arguments={"path": "/etc/passwd", "content": "x"})
    assert bad.status == "blocked"
    other = policy.evaluate(server_id="fs", tool_name="write_file",
                            context=CallContext(tenant_id="globex"),
                            arguments={"path": "a.txt", "content": "x"})
    assert other.status == "blocked" and "tenant" in other.reason


def test_allowlist_entry_without_report_applies_the_new_checks():
    srv = AllowlistedServer(server_id="s", clearance=R)
    policy = AllowlistPolicy(enabled=True, servers={"s": srv})
    assert policy.evaluate(server_id="s", tool_name="anything").status == "auto_approved"
    assert policy.evaluate(server_id="s", tool_name="anything",
                           context=CallContext(agent_tools=[])).status == "blocked"
    public = policy.evaluate(server_id="s", tool_name="get_page", argument_policy=ArgumentPolicy(),
                             arguments={"url": "https://x.test"})
    assert public.status == "auto_approved"  # the default pack lets public HTTP keep clearance
    held = policy.evaluate(server_id="s", tool_name="get_page", argument_policy=ArgumentPolicy(),
                           arguments={"url": "http://192.168.1.5/admin"})
    assert held.status == "requires_approval"


def test_without_the_new_inputs_decisions_are_unchanged():
    """Feature-absence guard: the 1.0 keywords alone never consult the new rules."""
    report = {**_report(("get_x", R)), "argument_policy": None}
    assert enforce_from_report(report, tool_name="get_x", execution_mode="AUTO").status == \
        "auto_approved"
