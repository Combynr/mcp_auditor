"""The built-in default pack: zero-setup protection that leaves ordinary calls alone.

The tool surfaces below are synthetic stand-ins for common kinds of MCP servers
(filesystem, git, fetch, email, spreadsheet). Each call is decided with an empty
``ArgumentPolicy()``, which is what a host gets without writing any rule.
"""
from __future__ import annotations

import pytest

from mcp_auditor import (
    ArgumentPolicy,
    ArgumentRule,
    ClearanceLevel,
    McpToolDescriptor,
    ToolArgumentSchema,
    audit_tool_surface_sync,
    describe_defaults,
    enforce_from_report,
)

SURFACES = {
    "filesystem": [
        McpToolDescriptor("read_file", "Read the complete contents of a file", {"properties": {"path": {}}}),
        McpToolDescriptor("read_multiple_files", "Read several files", {"properties": {"paths": {}}}),
        McpToolDescriptor("list_directory", "List a directory", {"properties": {"path": {}}}),
        McpToolDescriptor("search_files", "Search for files", {"properties": {"path": {}, "pattern": {}}}),
        McpToolDescriptor("get_file_info", "Get file metadata", {"properties": {"path": {}}}),
        McpToolDescriptor("write_file", "Create or overwrite a file", {"properties": {"path": {}, "content": {}}}),
        McpToolDescriptor("edit_file", "Edit a file", {"properties": {"path": {}, "edits": {}}}),
        McpToolDescriptor("move_file", "Move or rename a file", {"properties": {"source": {}, "destination": {}}}),
    ],
    "git": [
        McpToolDescriptor("git_status", "Show the working tree status", {"properties": {"repo_path": {}}}),
        McpToolDescriptor("git_log", "Show commit logs", {"properties": {"repo_path": {}, "max_count": {}}}),
        McpToolDescriptor("git_diff", "Show changes", {"properties": {"repo_path": {}, "target": {}}}),
        McpToolDescriptor("git_commit", "Record changes", {"properties": {"repo_path": {}, "message": {}}}),
    ],
    "fetch": [McpToolDescriptor("fetch", "Fetches a URL from the internet", {"properties": {"url": {}}})],
    "email": [
        McpToolDescriptor("search_emails", "Search messages", {"properties": {"query": {}}}),
        McpToolDescriptor("send_email", "Send an email", {"properties": {"to": {}, "subject": {}, "body": {}}}),
    ],
    "office": [
        McpToolDescriptor("read_range", "Read a worksheet range", {"properties": {"range": {}}}),
        McpToolDescriptor("write_range", "Write values to a worksheet range",
                          {"properties": {"range": {}, "values": {}}}),
    ],
}

POLICY = ArgumentPolicy()


def _report(server: str) -> dict:
    report = audit_tool_surface_sync(SURFACES[server]).to_dict()
    report["recommended_clearance"] = ClearanceLevel.READ_ONLY.value  # isolate the tool level
    return report


def _decide(server: str, tool: str, args: dict, *, policy=POLICY, mode="AUTO"):
    return enforce_from_report(_report(server), tool_name=tool, execution_mode=mode,
                               server_id=server, arguments=args, argument_policy=policy)


def _baseline(server: str, tool: str, args: dict):
    return enforce_from_report(_report(server), tool_name=tool, execution_mode="AUTO",
                               server_id=server, arguments=args)


ORDINARY = [
    ("filesystem", "read_file", {"path": "/home/user/project/README.md"}),
    ("filesystem", "read_multiple_files", {"paths": ["a.txt", "b/c.txt"]}),
    ("filesystem", "list_directory", {"path": "/home/user/project"}),
    ("filesystem", "search_files", {"path": ".", "pattern": "*.py"}),
    ("filesystem", "get_file_info", {"path": "notes.md"}),
    ("filesystem", "write_file", {"path": "/home/user/project/out.md", "content": "# Notes"}),
    ("filesystem", "edit_file", {"path": "src/app.py", "edits": [{"oldText": "a", "newText": "b"}]}),
    ("filesystem", "move_file", {"source": "a.txt", "destination": "archive/a.txt"}),
    ("git", "git_status", {"repo_path": "/home/user/project"}),
    ("git", "git_log", {"repo_path": "/home/user/project", "max_count": 10}),
    ("git", "git_diff", {"repo_path": "/home/user/project", "target": "main"}),
    ("git", "git_commit", {"repo_path": "/home/user/project", "message": "Fix typo"}),
    ("fetch", "fetch", {"url": "https://example.com/docs", "max_length": 5000}),
    ("email", "search_emails", {"query": "invoice"}),
    ("email", "send_email", {"to": ["Ana <ana@example.com>", "bo@example.org"], "subject": "Hi",
                             "body": "See you"}),
    ("office", "read_range", {"range": "A1:C10"}),
    ("office", "write_range", {"range": "A1:B2", "values": [[1, 2], [3, 4]]}),
]


@pytest.mark.parametrize("server, tool, args", ORDINARY)
def test_ordinary_calls_are_never_blocked_and_never_stricter_than_their_kind_needs(server, tool, args):
    decided = _decide(server, tool, args)
    assert decided.status != "blocked", decided.reason
    before = _baseline(server, tool, args)
    if before.status == "requires_approval":
        assert decided.status == "requires_approval"  # mutating tools: unchanged


@pytest.mark.parametrize("server, tool, args", [
    ("filesystem", "read_file", {"path": "/home/user/project/README.md"}),
    ("git", "git_status", {"repo_path": "/home/user/project"}),
    ("fetch", "fetch", {"url": "https://example.com/docs"}),
    ("email", "search_emails", {"query": "invoice"}),
    ("office", "read_range", {"range": "A1:C10"}),
])
def test_ordinary_reads_keep_auto_approval(server, tool, args):
    assert _baseline(server, tool, args).status == "auto_approved"
    assert _decide(server, tool, args).status == "auto_approved"


@pytest.mark.parametrize("server, tool, args, words", [
    ("filesystem", "write_file", {"path": "../../etc/cron.d/x", "content": "x"}, "'..'"),
    ("filesystem", "move_file", {"source": "a", "destination": "..\\..\\x"}, "'..'"),
    ("filesystem", "write_file", {"path": "a\x00b", "content": "x"}, "NUL"),
    ("filesystem", "write_file", {"path": 7, "content": "x"}, "must be a path"),
    ("filesystem", "write_file", {"path": "a", "content": "x" * 10_000_001}, "bytes"),
    ("fetch", "fetch", {"url": "file:///etc/passwd"}, "http or https"),
    ("fetch", "fetch", {"url": "https://user:pw@example.com/"}, "credentials"),
    ("email", "send_email", {"to": "a@example.com\r\nBcc: x@evil.test"}, "line break"),
    ("email", "send_email", {"to": [f"u{i}@example.com" for i in range(51)]}, "recipients"),
    ("email", "send_email", {"to": "not-an-address"}, "not valid"),
    ("office", "write_range", {"range": "A1", "values": [[0]] * 10_001}, "rows"),
])
def test_hostile_or_malformed_calls_are_blocked_with_zero_setup(server, tool, args, words):
    decided = _decide(server, tool, args, mode="HITL")
    assert decided.status == "blocked"
    assert words in decided.reason and "built-in" in decided.reason


@pytest.mark.parametrize("url", ["http://localhost:8080/", "http://127.0.0.1/", "http://10.0.0.4/",
                                 "http://169.254.169.254/latest/meta-data", "http://[::1]/",
                                 "http://intranet/", "http://printer.local/"])
def test_http_to_a_private_host_waits_for_a_person(url):
    decided = _decide("fetch", "fetch", {"url": url})
    assert decided.status == "requires_approval"
    assert "local" in decided.reason or "private" in decided.reason


def test_a_renamed_shell_is_still_held_and_checked():
    report = {"recommended_clearance": "READ_ONLY",
              "tools": [{"name": "get_report", "clearance": "READ_ONLY", "description": ""}]}
    held = enforce_from_report(report, tool_name="get_report", execution_mode="AUTO",
                               arguments={"command": "ls"}, argument_policy=POLICY)
    assert held.status == "requires_approval"
    blocked = enforce_from_report(report, tool_name="get_report", execution_mode="AUTO",
                                  arguments={"command": "x" * 9000}, argument_policy=POLICY)
    assert blocked.status == "blocked"


def test_the_workspace_root_binds_default_paths(tmp_path):
    policy = ArgumentPolicy(workspace_root=str(tmp_path))
    inside = _decide("filesystem", "write_file", {"path": "a.txt", "content": "x"}, policy=policy)
    assert inside.status == "requires_approval"
    outside = _decide("filesystem", "write_file", {"path": "/etc/passwd", "content": "x"},
                      policy=policy)
    assert outside.status == "blocked" and "workspace root" in outside.reason


def test_a_declared_schema_overrides_the_defaults():
    schema = ToolArgumentSchema(tool="fetch", family="http", arguments={
        "url": ArgumentRule(type="string", format="url", allowed_domains=("intranet.example",),
                            allowed_schemes=("http",)),
    })
    policy = ArgumentPolicy(schemas=(schema,))
    assert _decide("fetch", "fetch", {"url": "http://intranet.example/x"}, policy=policy).status \
        == "auto_approved"
    assert _decide("fetch", "fetch", {"url": "https://example.com/"}, policy=policy).status \
        == "blocked"


def test_defaults_can_be_switched_off_which_holds_instead():
    off = ArgumentPolicy(defaults=False)
    assert ArgumentPolicy.from_dict(off.to_dict()).defaults is False
    assert ArgumentPolicy.from_dict({}).defaults is True
    assert ArgumentPolicy.from_dict({"defaults": "false"}).defaults is True  # only a real false
    assert _decide("fetch", "fetch", {"url": "https://example.com/"}, policy=off).status \
        == "requires_approval"


def test_the_pack_describes_every_high_risk_family():
    families = {entry["family"] for entry in describe_defaults()}
    assert families == {"file_write", "shell", "email", "http", "office_write"}
    assert all(entry["summary"] for entry in describe_defaults())
