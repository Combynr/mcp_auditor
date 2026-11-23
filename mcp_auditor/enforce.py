"""Runtime disposition for a single MCP tool call."""
from __future__ import annotations

from typing import Any, Iterable

from .types import (
    ClearanceLevel,
    ToolCallDisposition,
    coerce_clearance,
    max_clearance,
)


def enforce_tool_call(
    *,
    server_clearance: ClearanceLevel,
    tool_clearance: ClearanceLevel,
    tool_name: str,
    execution_mode: str,
    server_id: str = "",
) -> ToolCallDisposition:
    """Decide auto-approve / require approval / block for one call.

    Only an effective ``READ_ONLY`` clearance in ``AUTO`` mode is auto-approved;
    every other combination needs a human or is refused.
    """
    effective = max_clearance(server_clearance, tool_clearance)

    if effective is ClearanceLevel.BLOCKED:
        return ToolCallDisposition(
            status="blocked",
            reason="MCP server/tool is BLOCKED by the auditor.",
            clearance=effective,
            tool_name=tool_name,
            server_id=server_id,
        )

    if effective is not ClearanceLevel.READ_ONLY:
        return ToolCallDisposition(
            status="requires_approval",
            reason=(
                "DRAFT_ONLY clearance: mutating MCP tool call requires human approval."
            ),
            clearance=effective,
            tool_name=tool_name,
            server_id=server_id,
        )

    normalized_mode = execution_mode.strip().upper() if isinstance(execution_mode, str) else ""
    if normalized_mode == "AUTO":
        return ToolCallDisposition(
            status="auto_approved",
            reason="READ_ONLY clearance: non-mutating MCP tool call auto-approved.",
            clearance=effective,
            tool_name=tool_name,
            server_id=server_id,
        )
    return ToolCallDisposition(
        status="requires_approval",
        reason="Execution mode requires human approval for this MCP tool call.",
        clearance=effective,
        tool_name=tool_name,
        server_id=server_id,
    )


def _blocked(reason: str, tool_name: Any, server_id: str) -> ToolCallDisposition:
    return ToolCallDisposition(
        status="blocked",
        reason=reason,
        clearance=ClearanceLevel.BLOCKED,
        tool_name=tool_name if isinstance(tool_name, str) else "",
        server_id=server_id,
    )


def _grant_denies(allowed_tools: Iterable[str] | None, tool_name: str) -> bool:
    """True when a per-tool grant exists and does not name ``tool_name`` exactly.

    A bare string is not a list of names; it is treated as an empty grant
    rather than as a set of single characters.
    """
    if allowed_tools is None:
        return False
    if isinstance(allowed_tools, (str, bytes)):
        return True
    return tool_name not in {t for t in allowed_tools if isinstance(t, str)}


def _drift_block(
    report: dict[str, Any],
    live_fingerprint: str | None,
    tool_name: str,
    server_id: str,
) -> ToolCallDisposition | None:
    """Block when the caller supplies a live fingerprint the audit does not match."""
    if live_fingerprint is None:
        return None
    expected = str(report.get("surface_fingerprint") or "")
    if expected and expected == live_fingerprint:
        return None
    return _blocked(
        "Tool surface changed since the audit (fingerprint mismatch or none on file); "
        "re-audit the server before calling its tools.",
        tool_name,
        server_id,
    )


def enforce_from_report(
    report: dict[str, Any],
    *,
    tool_name: str,
    execution_mode: str,
    server_id: str = "",
    allowed_tools: list[str] | None = None,
    live_fingerprint: str | None = None,
) -> ToolCallDisposition:
    """Runtime enforcement against a persisted audit report dict.

    ``allowed_tools`` (optional): when set, tools not in the grant list are blocked
    even if the server clearance would otherwise allow them.

    ``live_fingerprint`` (optional): the ``surface_fingerprint`` of the server's
    current tool list. When given and it differs from the report's fingerprint
    (or the report has none), the call is blocked until the server is re-audited,
    so neither a clearance nor a per-tool grant outlives a surface change.
    """
    if not isinstance(report, dict):
        report = {}
    if not isinstance(tool_name, str) or not tool_name.strip():
        return _blocked("MCP call has no tool name; refused.", tool_name, server_id)
    if _grant_denies(allowed_tools, tool_name):
        return _blocked(
            f"Tool '{tool_name}' is not on the per-tool allowlist for this server.",
            tool_name,
            server_id,
        )
    drift = _drift_block(report, live_fingerprint, tool_name, server_id)
    if drift is not None:
        return drift

    server_clearance = coerce_clearance(report.get("recommended_clearance"))
    matches = [
        coerce_clearance(tool.get("clearance"))
        for tool in (report.get("tools") or [])
        if isinstance(tool, dict) and tool.get("name") == tool_name
    ]
    if matches:
        # Duplicate names in an advertised surface: the strictest entry wins.
        tool_clearance = max_clearance(*matches)
    else:
        # A tool missing from the audited surface is never auto-approved.
        tool_clearance = max_clearance(server_clearance, ClearanceLevel.DRAFT_ONLY)
    return enforce_tool_call(
        server_clearance=server_clearance,
        tool_clearance=tool_clearance,
        tool_name=tool_name,
        execution_mode=execution_mode,
        server_id=server_id,
    )
