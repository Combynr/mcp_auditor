"""Who is calling, through which agent, with what arguments.

1.0 decided a call from the tool's clearance alone. 1.1 lets a host add three
more constraints, and a call must pass all of them (an intersection; none can
widen another):

1. **The caller's role**, as a set of capabilities the host derived from its own
   access control, and the caller's tenant when servers belong to one.
2. **The agent's tool list**, the tools the agent profile may use.
3. **Argument rules** (:mod:`mcp_auditor.arguments`), declared per tool.

Each is optional and checked only when the host supplies it, so 1.0 callers see
no change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .arguments import ToolArgumentSchema, validate_arguments
from .families import detect_families
from .types import ClearanceLevel

CAPABILITY_READ = "mcp:read"
CAPABILITY_WRITE = "mcp:write"


def required_capability(clearance: ClearanceLevel) -> str:
    """The capability a caller needs for a call at this clearance."""
    return CAPABILITY_READ if clearance is ClearanceLevel.READ_ONLY else CAPABILITY_WRITE


@dataclass(frozen=True)
class CallContext:
    """What the host knows about the caller.

    ``None`` means "not checked" for each field; an empty set means "nothing is
    allowed". ``agent_tools`` entries are a bare tool name, ``server:tool`` or
    ``server:*``.
    """

    capabilities: frozenset[str] | None = None
    tenant_id: str | None = None
    agent_tools: frozenset[str] | None = None
    workspace_root: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", _string_set(self.capabilities))
        object.__setattr__(self, "agent_tools", _string_set(self.agent_tools))

    def allows_agent_tool(self, server_id: str, tool_name: str) -> bool:
        if self.agent_tools is None:
            return True
        return bool({tool_name, f"{server_id}:{tool_name}", f"{server_id}:*"}
                    & self.agent_tools) if tool_name else False


@dataclass(frozen=True)
class ArgumentPolicy:
    """The declared argument schemas, and the workspace root paths must stay inside.

    With a policy in force, a call to a high-risk tool (file write or delete,
    shell, email, outbound HTTP, office write-back) that matches no declared
    schema by name is held for approval, never auto-approved.
    """

    schemas: tuple[ToolArgumentSchema, ...] = ()
    workspace_root: str | None = None

    def by_name(self, tool_name: str) -> list[ToolArgumentSchema]:
        return [s for s in self.schemas if tool_name in s.names]

    def by_shape(self, families: frozenset[str], arguments: Any) -> list[ToolArgumentSchema]:
        """Schemas a renamed tool still fits: same family, and its arguments fit."""
        if not isinstance(arguments, Mapping):
            return []
        keys = {str(k) for k in arguments}
        out = []
        for schema in self.schemas:
            if schema.family not in families:
                continue
            declared = set(schema.arguments)
            required = {k for k, r in schema.arguments.items() if r.required}
            if required <= keys and (keys & declared):
                out.append(schema)
        return out

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schemas": [s.to_dict() for s in self.schemas]}
        if self.workspace_root:
            out["workspace_root"] = self.workspace_root
        return out

    @classmethod
    def from_dict(cls, data: Any) -> ArgumentPolicy:
        """Parse a stored policy. A present but malformed policy still holds high-risk calls."""
        raw = data if isinstance(data, Mapping) else {}
        entries = raw.get("schemas") if isinstance(raw.get("schemas"), list) else []
        schemas = tuple(s for s in (ToolArgumentSchema.from_dict(e) for e in entries) if s)
        root = raw.get("workspace_root")
        return cls(schemas=schemas, workspace_root=root if isinstance(root, str) and root else None)


@dataclass
class PolicyOutcome:
    """The result of the context and argument checks for one call."""

    blocked_reason: str = ""
    floor: ClearanceLevel = ClearanceLevel.READ_ONLY
    floor_reason: str = ""
    capabilities: list[str] = field(default_factory=list)


def check_identity(
    context: CallContext | None, *, server_id: str, tool_name: str,
    server_tenant_id: str | None,
) -> str:
    """'' when tenant and agent profile allow the call; otherwise the reason.

    A server that names a tenant is refused to a caller who names none: the
    tenant is new in 1.1, so only a host that set it can hit this.
    """
    tenant = (server_tenant_id or "").strip()
    caller_tenant = (context.tenant_id or "").strip() if context is not None else ""
    if tenant and caller_tenant != tenant:
        return f"MCP server '{server_id}' belongs to another tenant; call refused."
    if context is None:
        return ""
    if not context.allows_agent_tool(server_id, tool_name):
        return f"Tool '{tool_name}' is not in this agent profile's tool list."
    return ""


def check_arguments(
    policy: ArgumentPolicy | None,
    *,
    tool_name: str,
    description: str,
    arguments: Any,
    context: CallContext | None,
) -> PolicyOutcome:
    """Apply the declared argument rules, or hold an undeclared high-risk call."""
    outcome = PolicyOutcome()
    if policy is None:
        return outcome
    root = (context.workspace_root if context and context.workspace_root else None) \
        or policy.workspace_root
    families = detect_families(tool_name, description, arguments)
    declared = policy.by_name(tool_name)
    matched = declared or (policy.by_shape(families, arguments) if families else [])
    if matched and arguments is None:
        outcome.floor = ClearanceLevel.DRAFT_ONLY
        outcome.floor_reason = (f"Tool '{tool_name}' has declared argument rules but the "
                                "call's arguments were not supplied; held for approval.")
        return outcome
    for schema in matched:
        problems = validate_arguments(schema, arguments, workspace_root=root)
        if problems:
            outcome.blocked_reason = (f"Tool '{tool_name}' arguments break the declared rules: "
                                      + "; ".join(problems[:5]) + ".")
            return outcome
        if schema.capability:
            outcome.capabilities.append(schema.capability)
    if not declared and families:
        outcome.floor = ClearanceLevel.DRAFT_ONLY
        outcome.floor_reason = (
            f"Tool '{tool_name}' looks like a {'/'.join(sorted(families))} tool and has no "
            "declared argument schema under that name; held for approval.")
    return outcome


def missing_capabilities(context: CallContext | None, needed: Iterable[str]) -> list[str]:
    if context is None or context.capabilities is None:
        return []
    return sorted({n for n in needed if n} - context.capabilities)


def _string_set(value: Any) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return frozenset()  # a bare string is not a list; read it as an empty grant
    return frozenset(v for v in value if isinstance(v, str))

