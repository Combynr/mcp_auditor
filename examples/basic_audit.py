"""Audit a tool surface, allowlist the server, and gate calls.

Run after installing the package: ``python examples/basic_audit.py``.
"""
from __future__ import annotations

from mcp_auditor import (
    AllowlistedServer,
    AllowlistPolicy,
    ClearanceLevel,
    McpToolDescriptor,
    audit_tool_surface_sync,
    detect_drift,
    surface_fingerprint,
)


def overseer(tools):
    """Stand-in for an LLM reviewer: return (verdict, rationale)."""
    return "SAFE", "list-only surface"


def main() -> None:
    issues = [
        McpToolDescriptor(name="list_issues", description="List issues in a repository"),
        McpToolDescriptor(name="create_issue", description="Create an issue"),
        McpToolDescriptor(name="run_shell", description="Execute arbitrary shell commands"),
    ]
    report = audit_tool_surface_sync(issues)
    print(report.summary)
    for risk in report.tools:
        print(f"  {risk.name:<14} {risk.category:<15} {risk.clearance.value}")
    assert report.recommended_clearance is ClearanceLevel.DRAFT_ONLY

    # A read-only surface reviewed as SAFE by an overseer may auto-approve.
    docs = [McpToolDescriptor(name="search_docs", description="Search the documentation")]
    docs_report = audit_tool_surface_sync(docs, overseer=overseer)
    assert docs_report.recommended_clearance is ClearanceLevel.READ_ONLY

    policy = AllowlistPolicy(enabled=True)
    policy.upsert(AllowlistedServer(
        server_id="issues",
        clearance=report.recommended_clearance,
        audit_report=report.to_dict(),
    ))
    policy.upsert(AllowlistedServer(
        server_id="docs",
        clearance=docs_report.recommended_clearance,
        audit_report=docs_report.to_dict(),
        allowed_tools=["search_docs"],
    ))

    checks = [
        ("issues", "list_issues", "requires_approval"),  # server floor is DRAFT_ONLY
        ("issues", "run_shell", "requires_approval"),
        ("docs", "search_docs", "auto_approved"),
        ("docs", "delete_docs", "blocked"),  # not in the per-tool grant
        ("unknown", "search_docs", "blocked"),  # not on the allowlist
    ]
    for server_id, tool_name, expected in checks:
        decision = policy.evaluate(server_id=server_id, tool_name=tool_name, execution_mode="AUTO")
        print(f"{server_id}/{tool_name}: {decision.status}")
        assert decision.status == expected, decision

    # The docs server changes a description after the audit: calls stop until re-audit.
    changed = [McpToolDescriptor(name="search_docs", description="Search, then delete, the docs")]
    print("drift:", detect_drift(docs_report, changed).reason)
    decision = policy.evaluate(
        server_id="docs", tool_name="search_docs", live_fingerprint=surface_fingerprint(changed)
    )
    print("docs/search_docs after drift:", decision.status)
    assert decision.status == "blocked"


if __name__ == "__main__":
    main()
