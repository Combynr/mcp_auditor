"""Audit an MCP tool surface (static classify + optional injectable Overseer)."""
from __future__ import annotations

import asyncio
import inspect
from typing import Sequence

from .classify import ClassificationPolicy, classify_tools, static_clearance
from .overseer import OverseerFn, overseer_floor
from .surface import surface_fingerprint
from .types import ClearanceLevel, McpToolDescriptor, ServerAuditReport, max_clearance

# UNAVAILABLE lets a host overseer report its own outage; it floors like REVIEW.
_VERDICTS = frozenset({"SAFE", "REVIEW", "MALICIOUS", "UNAVAILABLE"})

_SKIPPED_RATIONALE = (
    "Overseer evaluation disabled or not provided; static classification only. "
    "SKIPPED floors to DRAFT_ONLY — turning overseer off must not open auto-execute."
)


def _summarize(
    tool_risks: Sequence,
    clearance: ClearanceLevel,
    overseer_verdict: str,
) -> str:
    destructive = sum(1 for risk in tool_risks if risk.category == "destructive")
    mutating = sum(1 for risk in tool_risks if risk.category == "state_changing")
    read_only = sum(1 for risk in tool_risks if risk.category == "read_only")
    return (
        f"{len(tool_risks)} tool(s): {read_only} read-only, {mutating} state-changing, "
        f"{destructive} destructive. Overseer verdict: {overseer_verdict}. "
        f"Enforced clearance: {clearance.value}."
    )


def _build_report(
    tool_list: list[McpToolDescriptor],
    *,
    overseer_verdict: str,
    overseer_rationale: str,
    overseer_level: ClearanceLevel,
    policy: ClassificationPolicy | None,
) -> ServerAuditReport:
    tool_risks = classify_tools(tool_list, policy)
    static_level = static_clearance(tool_risks, policy)
    fingerprint = surface_fingerprint(tool_list)
    recommended = max_clearance(static_level, overseer_level)
    return ServerAuditReport(
        recommended_clearance=recommended,
        tools=tool_risks,
        overseer_verdict=overseer_verdict,
        overseer_rationale=overseer_rationale,
        summary=_summarize(tool_risks, recommended, overseer_verdict),
        static_clearance=static_level,
        surface_fingerprint=fingerprint,
    )


async def _invoke_overseer(
    overseer: OverseerFn,
    tools: Sequence[McpToolDescriptor],
) -> tuple[str, str]:
    result = overseer(tools)
    if inspect.isawaitable(result):
        result = await result  # type: ignore[misc]
    # Anything but a (str, str) pair is treated as an overseer failure.
    if (
        not isinstance(result, (tuple, list))
        or len(result) != 2
        or not isinstance(result[0], str)
        or not isinstance(result[1], str)
    ):
        raise TypeError(
            "overseer must return (verdict, rationale) strings, "
            f"got {type(result).__name__}"
        )
    verdict = result[0].strip().upper()
    if verdict not in _VERDICTS:
        raise ValueError(f"unknown overseer verdict {result[0][:40]!r}")
    return verdict, result[1]


async def audit_tool_surface(
    tools: Sequence[McpToolDescriptor],
    *,
    overseer: OverseerFn | None = None,
    use_overseer: bool = True,
    policy: ClassificationPolicy | None = None,
) -> ServerAuditReport:
    """Pure audit over an already-fetched tool surface.

    No I/O beyond the optional injectable Overseer. When ``use_overseer`` is False
    or no ``overseer`` is provided, verdict is SKIPPED and the floor is
    ``DRAFT_ONLY`` (same as UNAVAILABLE) — static-only must never grant open
    auto-execute. Hosts that want an LLM must inject one. Never imports
    application frameworks.
    """
    tool_list = list(tools)
    overseer_verdict = "SKIPPED"
    overseer_rationale = _SKIPPED_RATIONALE
    # Fail closed: SKIPPED ≡ human review floor (see overseer_floor).
    overseer_level = overseer_floor("SKIPPED")

    if use_overseer and tool_list:
        if overseer is None:
            overseer_verdict = "SKIPPED"
            overseer_rationale = (
                "No overseer callable injected; host must supply one for LLM review. "
                "SKIPPED floors to DRAFT_ONLY."
            )
            overseer_level = overseer_floor("SKIPPED")
        else:
            try:
                overseer_verdict, overseer_rationale = await _invoke_overseer(
                    overseer, tool_list
                )
            except Exception as error:  # noqa: BLE001 - fail closed
                overseer_verdict = "UNAVAILABLE"
                overseer_rationale = (
                    f"Overseer unavailable ({error}); defaulting to human review."
                )
            overseer_level = overseer_floor(overseer_verdict)

    return _build_report(
        tool_list,
        overseer_verdict=overseer_verdict,
        overseer_rationale=overseer_rationale,
        overseer_level=overseer_level,
        policy=policy,
    )


def audit_tool_surface_sync(
    tools: Sequence[McpToolDescriptor],
    *,
    overseer: OverseerFn | None = None,
    use_overseer: bool = True,
    policy: ClassificationPolicy | None = None,
) -> ServerAuditReport:
    """Sync entrypoint for scripts and sync hosts.

    Static-only when no ``overseer`` is passed (or ``use_overseer=False``); the
    verdict is then SKIPPED and floors to DRAFT_ONLY. With an overseer it runs
    ``audit_tool_surface`` via ``asyncio.run``, so it cannot be called from inside
    a running event loop (await ``audit_tool_surface`` there instead).
    """
    if not use_overseer or overseer is None:
        return _build_report(
            list(tools),
            overseer_verdict="SKIPPED",
            overseer_rationale=_SKIPPED_RATIONALE,
            overseer_level=overseer_floor("SKIPPED"),
            policy=policy,
        )
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            audit_tool_surface(
                tools, overseer=overseer, use_overseer=True, policy=policy
            )
        )
    raise RuntimeError(
        "Cannot run overseer synchronously inside an active event loop; "
        "await audit_tool_surface(...) instead."
    )
