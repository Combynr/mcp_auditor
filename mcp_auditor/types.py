"""Shared types for MCP tool-surface auditing and enforcement."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ClearanceLevel(str, Enum):
    """Enforced server/tool clearance (stricter wins via max_clearance)."""

    READ_ONLY = "READ_ONLY"
    DRAFT_ONLY = "DRAFT_ONLY"
    BLOCKED = "BLOCKED"


_CLEARANCE_RANK: dict[ClearanceLevel, int] = {
    ClearanceLevel.READ_ONLY: 0,
    ClearanceLevel.DRAFT_ONLY: 1,
    ClearanceLevel.BLOCKED: 2,
}


def max_clearance(*levels: ClearanceLevel | str) -> ClearanceLevel:
    """Return the strictest level. No levels, or unrecognised ones, count as DRAFT_ONLY.

    Inputs are coerced first: a plain string such as ``"BLOCKED"`` must not slip
    past the identity checks in ``enforce_tool_call`` as an unknown value.
    """
    if not levels:
        return ClearanceLevel.DRAFT_ONLY
    coerced = [coerce_clearance(level) for level in levels]
    return max(coerced, key=lambda level: _CLEARANCE_RANK[level])


def coerce_clearance(value: Any) -> ClearanceLevel:
    """Parse a clearance from an enum member or a string; anything else is DRAFT_ONLY."""
    if isinstance(value, ClearanceLevel):
        # str() of a (str, Enum) member is "ClearanceLevel.X", not "X".
        return value
    try:
        return ClearanceLevel(str(value).strip().upper())
    except (ValueError, AttributeError, TypeError):
        return ClearanceLevel.DRAFT_ONLY


@dataclass(slots=True)
class McpToolDescriptor:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema or {}),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> McpToolDescriptor:
        return cls(
            name=str(data.get("name") or ""),
            description=str(data.get("description") or ""),
            input_schema=dict(data.get("input_schema") or data.get("inputSchema") or {}),
        )


@dataclass(slots=True)
class ToolRisk:
    name: str
    category: str  # "read_only" | "state_changing" | "destructive"
    clearance: ClearanceLevel
    signals: list[str]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "clearance": self.clearance.value,
            "signals": list(self.signals),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRisk:
        return cls(
            name=str(data.get("name") or ""),
            category=str(data.get("category") or "state_changing"),
            clearance=coerce_clearance(data.get("clearance")),
            signals=list(data.get("signals") or []),
            description=str(data.get("description") or ""),
        )


@dataclass(slots=True)
class ServerAuditReport:
    recommended_clearance: ClearanceLevel
    tools: list[ToolRisk]
    overseer_verdict: str
    overseer_rationale: str
    summary: str
    static_clearance: ClearanceLevel
    surface_fingerprint: str = ""

    @property
    def tool_count(self) -> int:
        return len(self.tools)

    def clearance_for_tool(self, tool_name: str) -> ClearanceLevel:
        matches = [tool.clearance for tool in self.tools if tool.name == tool_name]
        if matches and tool_name:
            # A server may advertise the same name twice; the strictest entry wins.
            return max_clearance(*matches)
        # Unknown tool on an audited server — never auto-approve.
        return max_clearance(self.recommended_clearance, ClearanceLevel.DRAFT_ONLY)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommended_clearance": self.recommended_clearance.value,
            "static_clearance": self.static_clearance.value,
            "tool_count": self.tool_count,
            "tools": [tool.to_dict() for tool in self.tools],
            "overseer_verdict": self.overseer_verdict,
            "overseer_rationale": self.overseer_rationale,
            "summary": self.summary,
            "surface_fingerprint": self.surface_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerAuditReport:
        tools = [
            ToolRisk.from_dict(t) if isinstance(t, dict) else t
            for t in (data.get("tools") or [])
            if isinstance(t, (dict, ToolRisk))
        ]
        return cls(
            recommended_clearance=coerce_clearance(data.get("recommended_clearance")),
            tools=tools,
            overseer_verdict=str(data.get("overseer_verdict") or ""),
            overseer_rationale=str(data.get("overseer_rationale") or ""),
            summary=str(data.get("summary") or ""),
            static_clearance=coerce_clearance(
                data.get("static_clearance") or data.get("recommended_clearance")
            ),
            surface_fingerprint=str(data.get("surface_fingerprint") or ""),
        )


@dataclass(slots=True)
class ToolCallDisposition:
    status: str  # "auto_approved" | "requires_approval" | "blocked"
    reason: str
    clearance: ClearanceLevel
    tool_name: str
    server_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = {
            "status": self.status,
            "reason": self.reason,
            "clearance": self.clearance.value,
            "tool_name": self.tool_name,
        }
        if self.server_id:
            out["server_id"] = self.server_id
        return out


@dataclass(slots=True)
class McpServerTarget:
    """Optional transport target for live tool enumeration (requires `mcp` SDK)."""

    transport: str  # "stdio" | "http"
    command: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    headers: dict[str, str] | None = None
    server_url: str = ""
    timeout_seconds: int = 30

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "command": list(self.command or []),
            "env": dict(self.env or {}) if self.env else None,
            "headers": dict(self.headers or {}) if self.headers else None,
            "server_url": self.server_url,
            "timeout_seconds": self.timeout_seconds,
        }
