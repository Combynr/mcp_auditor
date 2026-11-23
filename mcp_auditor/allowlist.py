"""Portable MCP allowlist policy (YAML/JSON friendly, no DB).

Hosts persist ``AllowlistPolicy.to_dict()`` however they like (SQL, YAML, JSON).
Runtime calls ``evaluate()`` before any MCP ``call_tool``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enforce import _drift_block, _grant_denies, enforce_from_report, enforce_tool_call
from .types import ClearanceLevel, ToolCallDisposition, coerce_clearance


@dataclass
class AllowlistedServer:
    server_id: str
    display_name: str = ""
    status: str = "active"  # active | revoked
    clearance: ClearanceLevel = ClearanceLevel.DRAFT_ONLY
    recommended_clearance: ClearanceLevel = ClearanceLevel.DRAFT_ONLY
    audit_report: dict[str, Any] = field(default_factory=dict)
    # None = no per-tool grant (each tool gets its audited clearance; tools absent
    # from the audit floor to DRAFT_ONLY). A list = only these exact names; every
    # other tool is blocked.
    allowed_tools: list[str] | None = None
    transport: str = ""
    endpoint: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        # A plain string here would otherwise crash evaluate() or be misread.
        self.clearance = coerce_clearance(self.clearance)
        self.recommended_clearance = coerce_clearance(self.recommended_clearance)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "display_name": self.display_name,
            "status": self.status,
            "clearance": self.clearance.value,
            "recommended_clearance": self.recommended_clearance.value,
            "audit_report": dict(self.audit_report or {}),
            "allowed_tools": (
                None if self.allowed_tools is None else list(self.allowed_tools)
            ),
            "transport": self.transport,
            "endpoint": self.endpoint,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AllowlistedServer:
        tools = data.get("allowed_tools")
        if tools is not None:
            # Malformed grants (a bare string, a number) become an empty grant.
            tools = (
                [t for t in tools if isinstance(t, str)]
                if isinstance(tools, (list, tuple))
                else []
            )
        return cls(
            server_id=str(data.get("server_id") or ""),
            display_name=str(data.get("display_name") or ""),
            status=str(data.get("status") or "active"),
            clearance=coerce_clearance(data.get("clearance")),
            recommended_clearance=coerce_clearance(
                data.get("recommended_clearance") or data.get("clearance")
            ),
            audit_report=dict(data.get("audit_report") or {}),
            allowed_tools=tools,
            transport=str(data.get("transport") or ""),
            endpoint=str(data.get("endpoint") or ""),
            note=str(data.get("note") or ""),
        )


@dataclass
class AllowlistPolicy:
    """Master MCP gate: a host calls ``evaluate()`` before every MCP tool call."""

    enabled: bool = False
    servers: dict[str, AllowlistedServer] = field(default_factory=dict)
    # When enabled=False, all MCP calls are blocked (fail closed).
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "note": self.note,
            "servers": {
                sid: srv.to_dict() for sid, srv in sorted(self.servers.items())
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AllowlistPolicy:
        raw = data or {}
        servers: dict[str, AllowlistedServer] = {}
        for sid, entry in (raw.get("servers") or {}).items():
            if isinstance(entry, dict):
                entry = {**entry, "server_id": entry.get("server_id") or sid}
                srv = AllowlistedServer.from_dict(entry)
                if srv.server_id:
                    servers[srv.server_id] = srv
        return cls(
            enabled=_parse_enabled(raw.get("enabled", False)),
            servers=servers,
            note=str(raw.get("note") or ""),
        )

    def upsert(self, server: AllowlistedServer) -> None:
        self.servers[server.server_id] = server

    def revoke(self, server_id: str) -> bool:
        srv = self.servers.get(server_id)
        if not srv:
            return False
        srv.status = "revoked"
        return True

    def evaluate(
        self,
        *,
        server_id: str,
        tool_name: str,
        execution_mode: str = "AUTO",
        live_fingerprint: str | None = None,
    ) -> ToolCallDisposition:
        """Decide one call. Anything not explicitly allowed is refused or sent to a human.

        Pass ``live_fingerprint`` (``surface_fingerprint`` of the server's current
        tools) to block calls when the surface no longer matches the audit.
        """
        if self.enabled is not True:
            return ToolCallDisposition(
                status="blocked",
                reason="MCP allowlist is disabled (master off); all MCP calls refused.",
                clearance=ClearanceLevel.BLOCKED,
                tool_name=tool_name,
                server_id=server_id,
            )
        sid = server_id.strip() if isinstance(server_id, str) else ""
        if not sid:
            return ToolCallDisposition(
                status="blocked",
                reason="MCP call missing server_id; register the server first.",
                clearance=ClearanceLevel.BLOCKED,
                tool_name=tool_name,
                server_id="",
            )
        srv = self.servers.get(sid)
        if srv is None:
            return ToolCallDisposition(
                status="blocked",
                reason=f"MCP server '{sid}' is not on the allowlist.",
                clearance=ClearanceLevel.BLOCKED,
                tool_name=tool_name,
                server_id=sid,
            )
        if srv.status != "active":
            return ToolCallDisposition(
                status="blocked",
                reason=f"MCP server '{sid}' is {srv.status}; calls are refused.",
                clearance=ClearanceLevel.BLOCKED,
                tool_name=tool_name,
                server_id=sid,
            )
        if srv.audit_report:
            report = dict(srv.audit_report)
            # Persisted (possibly overridden) clearance is authoritative.
            report["recommended_clearance"] = srv.clearance.value
            # An audited surface with zero tools still counts as audited: any
            # tool called on it is unknown and floors to DRAFT_ONLY.
            return enforce_from_report(
                report,
                tool_name=tool_name,
                execution_mode=execution_mode,
                server_id=sid,
                allowed_tools=srv.allowed_tools,
                live_fingerprint=live_fingerprint,
            )
        # Allowlist entry without any audit report — enforce server clearance only.
        if not isinstance(tool_name, str) or not tool_name.strip():
            return ToolCallDisposition(
                status="blocked",
                reason="MCP call has no tool name; refused.",
                clearance=ClearanceLevel.BLOCKED,
                tool_name="",
                server_id=sid,
            )
        drift = _drift_block({}, live_fingerprint, tool_name, sid)
        if drift is not None:
            return drift
        if _grant_denies(srv.allowed_tools, tool_name):
            return ToolCallDisposition(
                status="blocked",
                reason=f"Tool '{tool_name}' is not on the per-tool allowlist.",
                clearance=ClearanceLevel.BLOCKED,
                tool_name=tool_name,
                server_id=sid,
            )
        return enforce_tool_call(
            server_clearance=srv.clearance,
            tool_clearance=srv.clearance,
            tool_name=tool_name,
            execution_mode=execution_mode,
            server_id=sid,
        )


def _parse_enabled(value: Any) -> bool:
    """Only an explicit yes turns the master switch on; ``"false"`` must not."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "1"}
    return False
