"""mcp:auditor — a fail-closed gate for Model Context Protocol tool calls.

Framework-free classification, clearance, allowlist policy, and runtime
enforcement for MCP servers. The host application supplies persistence, UI,
and, optionally, an overseer LLM.
"""
from __future__ import annotations

from .__version__ import __version__
from .allowlist import AllowlistedServer, AllowlistPolicy
from .arguments import ArgumentRule, ToolArgumentSchema, path_problem, validate_arguments
from .audit import audit_tool_surface, audit_tool_surface_sync
from .callpolicy import (
    CAPABILITY_READ,
    CAPABILITY_WRITE,
    ArgumentPolicy,
    CallContext,
    required_capability,
)
from .classify import (
    ClassificationPolicy,
    DEFAULT_POLICY,
    classify_tool,
    classify_tools,
    static_clearance,
    tokens,
)
from .enforce import enforce_from_report, enforce_tool_call
from .defaults import DEFAULT_PACK, check_defaults, describe_defaults
from .families import HIGH_RISK_FAMILIES, detect_families
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
    "ArgumentPolicy",
    "ArgumentRule",
    "CAPABILITY_READ",
    "CAPABILITY_WRITE",
    "CallContext",
    "ClassificationPolicy",
    "ClearanceLevel",
    "DEFAULT_PACK",
    "DEFAULT_POLICY",
    "HIGH_RISK_FAMILIES",
    "McpServerTarget",
    "McpToolDescriptor",
    "OverseerFn",
    "ServerAuditReport",
    "SurfaceDrift",
    "ToolArgumentSchema",
    "ToolCallDisposition",
    "ToolRisk",
    "audit_server",
    "audit_tool_surface",
    "audit_tool_surface_sync",
    "build_overseer_prompt",
    "classify_tool",
    "classify_tools",
    "check_defaults",
    "coerce_clearance",
    "describe_defaults",
    "detect_drift",
    "detect_families",
    "enforce_from_report",
    "enforce_tool_call",
    "extract_response_text",
    "fetch_server_tools",
    "max_clearance",
    "overseer_floor",
    "parse_overseer_text",
    "path_problem",
    "required_capability",
    "serialize_tool_list",
    "static_clearance",
    "surface_fingerprint",
    "tokens",
    "validate_arguments",
]
