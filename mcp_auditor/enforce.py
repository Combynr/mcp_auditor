"""Runtime disposition for a single MCP tool call."""
from __future__ import annotations

from typing import Any, Iterable

from .callpolicy import (
    ArgumentPolicy,
    CallContext,
    check_arguments,
    check_identity,
    missing_capabilities,
    required_capability,
)
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
    server_floor: str = "",
    tool_floor: str = "",
) -> ToolCallDisposition:
    """Decide auto-approve / require approval / block for one call.

    Only an effective ``READ_ONLY`` clearance in ``AUTO`` mode is auto-approved;
    every other combination needs a human or is refused. 1.1.1: a held call's reason
    names the floor that applied, the server's clearance or the tool's classification
    (``server_floor`` / ``tool_floor`` add why, when the caller knows).
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
            reason=_floor_reason(server_clearance, tool_clearance,
                                 server_floor, tool_floor),
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


def _floor_reason(server_clearance: ClearanceLevel, tool_clearance: ClearanceLevel,
                  server_floor: str, tool_floor: str) -> str:
    """Which floor holds the call at DRAFT_ONLY. 1.1.0 always said "mutating", which
    misled when a read-only tool was held by its server's clearance."""
    parts = []
    if coerce_clearance(server_clearance) is not ClearanceLevel.READ_ONLY:
        parts.append("the server's clearance is DRAFT_ONLY"
                     + (f" ({server_floor})" if server_floor else ""))
    if coerce_clearance(tool_clearance) is not ClearanceLevel.READ_ONLY:
        parts.append("the tool is classified DRAFT_ONLY"
                     + (f" ({tool_floor})" if tool_floor else ""))
    return ("DRAFT_ONLY clearance: this MCP tool call requires human approval. Floor: "
            + ("; ".join(parts) or "DRAFT_ONLY") + ".")


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
    arguments: Any = None,
    context: CallContext | None = None,
    argument_policy: ArgumentPolicy | None = None,
    server_tenant_id: str | None = None,
) -> ToolCallDisposition:
    """Runtime enforcement against a persisted audit report dict.

    ``allowed_tools`` (optional): when set, tools not in the grant list are blocked
    even if the server clearance would otherwise allow them.

    ``live_fingerprint`` (optional): the ``surface_fingerprint`` of the server's
    current tool list. When given and it differs from the report's fingerprint
    (or the report has none), the call is blocked until the server is re-audited,
    so neither a clearance nor a per-tool grant outlives a surface change.

    1.1 additions, each checked only when given (see :mod:`mcp_auditor.callpolicy`):
    ``context`` (the caller's capabilities, tenant and agent tool list, with
    ``server_tenant_id`` the server's tenant), ``argument_policy`` (declared
    argument rules; a report dict may also carry one under ``"argument_policy"``)
    and ``arguments`` (the call's arguments, validated against that policy).
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

    refused = check_identity(context, server_id=server_id, tool_name=tool_name,
                             server_tenant_id=server_tenant_id)
    if refused:
        return _blocked(refused, tool_name, server_id)

    server_clearance = coerce_clearance(report.get("recommended_clearance"))
    entries = [
        tool for tool in (report.get("tools") or [])
        if isinstance(tool, dict) and tool.get("name") == tool_name
    ]
    matches = [coerce_clearance(tool.get("clearance")) for tool in entries]
    if matches:
        # Duplicate names in an advertised surface: the strictest entry wins.
        tool_clearance = max_clearance(*matches)
        tool_floor = "; ".join(str(sig) for tool in entries
                               for sig in (tool.get("signals") or [])
                               if isinstance(sig, str))[:300]
    else:
        # A tool missing from the audited surface is never auto-approved.
        tool_clearance = max_clearance(server_clearance, ClearanceLevel.DRAFT_ONLY)
        tool_floor = "not in the audited tool surface"
    verdict = str(report.get("overseer_verdict") or "")
    server_floor = ("as stored for the server; its audit's overseer verdict was " + verdict
                    + (", which floors a server to DRAFT_ONLY"
                       if verdict in ("SKIPPED", "UNAVAILABLE", "REVIEW") else "")
                    ) if verdict else "as stored for the server"
    return _decide_with_policy(
        server_clearance=server_clearance,
        tool_clearance=tool_clearance,
        tool_name=tool_name,
        execution_mode=execution_mode,
        server_id=server_id,
        description=" ".join(str(t.get("description") or "") for t in entries),
        arguments=arguments,
        context=context,
        argument_policy=_policy_for(report, argument_policy),
        server_floor=server_floor,
        tool_floor=tool_floor,
    )


def _policy_for(report: dict[str, Any], given: ArgumentPolicy | None) -> ArgumentPolicy | None:
    if given is not None:
        return given
    if "argument_policy" in report and report["argument_policy"] is not None:
        return ArgumentPolicy.from_dict(report["argument_policy"])
    return None


def _decide_with_policy(
    *,
    server_clearance: ClearanceLevel,
    tool_clearance: ClearanceLevel,
    tool_name: str,
    execution_mode: str,
    server_id: str,
    description: str,
    arguments: Any,
    context: CallContext | None,
    argument_policy: ArgumentPolicy | None,
    server_floor: str = "",
    tool_floor: str = "",
) -> ToolCallDisposition:
    """The 1.0 decision, then the 1.1 argument and capability checks on top of it."""
    base = enforce_tool_call(
        server_clearance=server_clearance,
        tool_clearance=tool_clearance,
        tool_name=tool_name,
        execution_mode=execution_mode,
        server_id=server_id,
        server_floor=server_floor,
        tool_floor=tool_floor,
    )
    if base.status == "blocked" or (argument_policy is None and context is None):
        return base
    outcome = check_arguments(argument_policy, tool_name=tool_name, description=description,
                              arguments=arguments, context=context)
    if outcome.blocked_reason:
        return _blocked(outcome.blocked_reason, tool_name, server_id)
    decision = base
    if outcome.floor is not ClearanceLevel.READ_ONLY:
        decision = enforce_tool_call(
            server_clearance=server_clearance,
            tool_clearance=max_clearance(tool_clearance, outcome.floor),
            tool_name=tool_name,
            execution_mode=execution_mode,
            server_id=server_id,
        )
        if base.status == "auto_approved":
            decision.reason = outcome.floor_reason
    lacking = missing_capabilities(
        context, [required_capability(decision.clearance), *outcome.capabilities])
    if lacking:
        return _blocked(
            f"The caller's role does not grant {', '.join(lacking)} for tool '{tool_name}'.",
            tool_name, server_id)
    return decision
