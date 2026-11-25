"""Declared argument rules for MCP tool calls.

A host declares, per tool, the arguments it accepts: strict types, numeric
floors and caps, paths that must stay inside a workspace root, allowlisted
recipients and domains, and item and byte limits. A call that breaks a rule is
blocked with a reason naming the argument; human approval cannot override it.

Everything is fail closed: an unknown type, a malformed limit, a path rule with
no workspace root, or an email or URL rule with no allowlist refuses the call
rather than letting it through unchecked.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

_TYPES = frozenset({"string", "integer", "number", "boolean", "array", "object"})
_FORMATS = frozenset({"", "path", "email", "url", "domain"})


@dataclass(frozen=True)
class ArgumentRule:
    """One argument. ``type`` is checked strictly: ``"2499"`` is not an integer and
    ``True`` is not a number."""

    type: str
    required: bool = False
    minimum: float | None = None
    maximum: float | None = None
    max_length: int | None = None
    max_bytes: int | None = None
    max_items: int | None = None
    enum: tuple[Any, ...] | None = None
    format: str = ""
    allowed_domains: tuple[str, ...] = ()
    allowed_recipients: tuple[str, ...] = ()
    allowed_schemes: tuple[str, ...] = ("https",)
    items: ArgumentRule | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type}
        for key in ("minimum", "maximum", "max_length", "max_bytes", "max_items"):
            if getattr(self, key) is not None:
                out[key] = getattr(self, key)
        if self.required:
            out["required"] = True
        if self.enum is not None:
            out["enum"] = list(self.enum)
        if self.format:
            out["format"] = self.format
        if self.allowed_domains:
            out["allowed_domains"] = list(self.allowed_domains)
        if self.allowed_recipients:
            out["allowed_recipients"] = list(self.allowed_recipients)
        if self.allowed_schemes != ("https",):
            out["allowed_schemes"] = list(self.allowed_schemes)
        if self.items is not None:
            out["items"] = self.items.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: Any) -> ArgumentRule:
        """Parse a rule. Anything malformed becomes a rule no value can satisfy."""
        if not isinstance(data, Mapping):
            return cls(type="<invalid>")
        try:
            items = data.get("items")
            return cls(
                type=str(data.get("type") or ""),
                required=data.get("required") is True,
                minimum=_limit(data.get("minimum"), number=True),
                maximum=_limit(data.get("maximum"), number=True),
                max_length=_limit(data.get("max_length")),
                max_bytes=_limit(data.get("max_bytes")),
                max_items=_limit(data.get("max_items")),
                enum=tuple(data["enum"]) if isinstance(data.get("enum"), list) else None,
                format=str(data.get("format") or ""),
                allowed_domains=_strings(data.get("allowed_domains")),
                allowed_recipients=_strings(data.get("allowed_recipients")),
                allowed_schemes=_strings(data.get("allowed_schemes")) or ("https",),
                items=cls.from_dict(items) if items is not None else None,
            )
        except (TypeError, ValueError):
            return cls(type="<invalid>")


@dataclass(frozen=True)
class ToolArgumentSchema:
    """The declared arguments of one tool (and the names it may be published under)."""

    tool: str
    arguments: dict[str, ArgumentRule] = field(default_factory=dict)
    aliases: tuple[str, ...] = ()
    family: str = ""
    capability: str = ""
    allow_additional: bool = False
    max_total_bytes: int | None = None

    @property
    def names(self) -> frozenset[str]:
        return frozenset({self.tool, *self.aliases}) - {""}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool": self.tool,
            "arguments": {k: v.to_dict() for k, v in sorted(self.arguments.items())},
        }
        if self.aliases:
            out["aliases"] = list(self.aliases)
        if self.family:
            out["family"] = self.family
        if self.capability:
            out["capability"] = self.capability
        if self.allow_additional:
            out["allow_additional"] = True
        if self.max_total_bytes is not None:
            out["max_total_bytes"] = self.max_total_bytes
        return out

    @classmethod
    def from_dict(cls, data: Any) -> ToolArgumentSchema | None:
        if not isinstance(data, Mapping) or not str(data.get("tool") or "").strip():
            return None
        raw_args = data.get("arguments")
        rules = (
            {str(k): ArgumentRule.from_dict(v) for k, v in raw_args.items()}
            if isinstance(raw_args, Mapping)
            else {"<invalid>": ArgumentRule(type="<invalid>", required=True)}
        )
        try:
            total = _limit(data.get("max_total_bytes"))
        except (TypeError, ValueError):
            total = 0  # a malformed cap refuses every call rather than none
        return cls(
            tool=str(data["tool"]).strip(),
            arguments=rules,
            aliases=_strings(data.get("aliases")),
            family=str(data.get("family") or ""),
            capability=str(data.get("capability") or ""),
            allow_additional=data.get("allow_additional") is True,
            max_total_bytes=total,
        )


def validate_arguments(
    schema: ToolArgumentSchema,
    arguments: Mapping[str, Any],
    *,
    workspace_root: str | None = None,
) -> list[str]:
    """Every rule the call breaks, as readable reasons. Empty means the call conforms."""
    if not isinstance(arguments, Mapping):
        return ["arguments must be an object"]
    problems: list[str] = []
    for name, rule in sorted(schema.arguments.items()):
        if name not in arguments:
            if rule.required:
                problems.append(f"argument '{name}' is required")
            continue
        problems.extend(_check(name, arguments[name], rule, workspace_root))
    if not schema.allow_additional:
        extra = sorted(str(k) for k in arguments if k not in schema.arguments)
        if extra:
            problems.append("undeclared arguments: " + ", ".join(extra))
    if schema.max_total_bytes is not None:
        size = _json_bytes(arguments)
        if size is None or size > schema.max_total_bytes:
            problems.append(f"arguments exceed {schema.max_total_bytes} bytes")
    return problems


def _check(name: str, value: Any, rule: ArgumentRule, root: str | None) -> list[str]:
    if rule.type not in _TYPES or rule.format not in _FORMATS:
        return [f"argument '{name}' has an invalid rule; refused"]
    if not _type_ok(value, rule.type):
        return [f"argument '{name}' must be {rule.type}, got {type(value).__name__}"]
    out: list[str] = []
    if rule.enum is not None and not any(_same(value, e) for e in rule.enum):
        out.append(f"argument '{name}' is not one of the allowed values")
    if rule.type in ("integer", "number"):
        if rule.minimum is not None and value < rule.minimum:
            out.append(f"argument '{name}' is below the minimum {rule.minimum:g}")
        if rule.maximum is not None and value > rule.maximum:
            out.append(f"argument '{name}' is above the maximum {rule.maximum:g}")
    if rule.type == "string":
        if rule.max_length is not None and len(value) > rule.max_length:
            out.append(f"argument '{name}' is longer than {rule.max_length} characters")
        out.extend(_format_problems(name, value, rule, root))
    if rule.type in ("array", "object"):
        if rule.max_items is not None and len(value) > rule.max_items:
            out.append(f"argument '{name}' has more than {rule.max_items} items")
        if rule.type == "array" and rule.items is not None:
            for index, item in enumerate(value):
                out.extend(_check(f"{name}[{index}]", item, rule.items, root))
                if len(out) > 20:
                    break
    if rule.max_bytes is not None:
        size = len(value.encode("utf-8")) if isinstance(value, str) else _json_bytes(value)
        if size is None or size > rule.max_bytes:
            out.append(f"argument '{name}' is larger than {rule.max_bytes} bytes")
    return out


def _type_ok(value: Any, kind: str) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(value))
    if kind == "array":
        return isinstance(value, (list, tuple))
    return isinstance(value, Mapping)


def _same(value: Any, allowed: Any) -> bool:
    # 1 == True in Python; an enum of [1] must not accept True.
    return type(value) is type(allowed) and value == allowed


def _format_problems(name: str, value: str, rule: ArgumentRule, root: str | None) -> list[str]:
    if rule.format == "path":
        why = path_problem(value, root)
    elif rule.format == "email":
        why = _email_problem(value, rule)
    elif rule.format == "url":
        why = _url_problem(value, rule)
    elif rule.format == "domain":
        why = "" if _domain_allowed(value.strip().lower(), rule.allowed_domains) else (
            "is not an allowed domain")
    else:
        why = ""
    return [f"argument '{name}' {why}"] if why else []


def path_problem(value: str, root: str | None) -> str:
    """'' when ``value`` resolves inside ``root``; otherwise why it does not."""
    if not root:
        return "is a path but no workspace root is configured; refused"
    if not value.strip() or "\x00" in value:
        return "is not a usable path"
    base = os.path.realpath(root)
    candidate = value if os.path.isabs(value) else os.path.join(base, value)
    resolved = os.path.realpath(candidate)
    try:
        inside = os.path.commonpath([base, resolved]) == base
    except ValueError:  # different drives on Windows
        inside = False
    return "" if inside else "resolves outside the workspace root"


def _email_problem(value: str, rule: ArgumentRule) -> str:
    address = value.strip()
    if (address.count("@") != 1 or any(c in address for c in " ,;<>\r\n\t\"'")
            or address.startswith("@") or address.endswith("@")):
        return "is not a single bare email address"
    if not rule.allowed_recipients and not rule.allowed_domains:
        return "has no recipient or domain allowlist declared; refused"
    lowered = address.lower()
    if lowered in {r.strip().lower() for r in rule.allowed_recipients}:
        return ""
    if _domain_allowed(lowered.rsplit("@", 1)[1], rule.allowed_domains):
        return ""
    return "is not an allowed recipient"


def _url_problem(value: str, rule: ArgumentRule) -> str:
    try:
        parts = urlsplit(value.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return "is not a valid URL"
    if parts.scheme.lower() not in {s.lower() for s in rule.allowed_schemes}:
        return f"must use one of the schemes {', '.join(rule.allowed_schemes)}"
    if not host or parts.username is not None or parts.password is not None:
        return "must name a host and carry no credentials"
    if not rule.allowed_domains:
        return "has no domain allowlist declared; refused"
    return "" if _domain_allowed(host, rule.allowed_domains) else "is not an allowed domain"


def _domain_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    """Exact match, or ``*.example.com`` for strict subdomains of example.com."""
    host = host.rstrip(".")
    for entry in allowed:
        entry = entry.strip().lower().rstrip(".")
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif entry and host == entry:
            return True
    return False


def _json_bytes(value: Any) -> int | None:
    try:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return None


def _limit(value: Any, *, number: bool = False) -> Any:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("limits must be numbers")
    if number:
        if not math.isfinite(value):
            raise ValueError("limits must be finite")
        return value
    if not isinstance(value, int) or value < 0:
        raise ValueError("sizes must be non-negative integers")
    return value


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(v) for v in value if isinstance(v, str) and v.strip())
