"""mcp:auditor — a fail-closed gate for Model Context Protocol tool calls.

Framework-free classification, clearance, allowlist policy, and runtime
enforcement for MCP servers. The host application supplies persistence, UI,
and, optionally, an overseer LLM.
"""
from __future__ import annotations

from .__version__ import __version__
from .allowlist import AllowlistedServer, AllowlistPolicy
from .audit import audit_tool_surface, audit_tool_surface_sync
from .classify import (
    ClassificationPolicy,
    DEFAULT_POLICY,
    classify_tool,
    classify_tools,
    static_clearance,
    tokens,
)
from .enforce import enforce_from_report, enforce_tool_call
from .fetch import audit_server, fetch_server_tools, serialize_tool_list
from .overseer import (
    OverseerFn,
    build_overseer_prompt,
    extract_response_text,
    overseer_floor,
    parse_overseer_text,
)
from .surface import SurfaceDrift, detect_drift, surface_fingerprint
from .types import (
    ClearanceLevel,
    McpServerTarget,
    McpToolDescriptor,
    ServerAuditReport,
    ToolCallDisposition,
    ToolRisk,
    coerce_clearance,
    max_clearance,
)

__all__ = [
    "__version__",
    "AllowlistPolicy",
    "AllowlistedServer",
    "ClassificationPolicy",
    "ClearanceLevel",
    "DEFAULT_POLICY",
    "McpServerTarget",
    "McpToolDescriptor",
    "OverseerFn",
    "ServerAuditReport",
    "SurfaceDrift",
    "ToolCallDisposition",
    "ToolRisk",
    "audit_server",
    "audit_tool_surface",
    "audit_tool_surface_sync",
    "build_overseer_prompt",
    "classify_tool",
    "classify_tools",
    "coerce_clearance",
    "detect_drift",
    "enforce_from_report",
    "enforce_tool_call",
    "extract_response_text",
    "fetch_server_tools",
    "max_clearance",
    "overseer_floor",
    "parse_overseer_text",
    "serialize_tool_list",
    "static_clearance",
    "surface_fingerprint",
    "tokens",
]
