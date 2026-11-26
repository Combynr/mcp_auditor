"""Tool-surface fingerprinting and drift detection."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from .types import McpToolDescriptor, ServerAuditReport


def surface_fingerprint(tools: Sequence[McpToolDescriptor]) -> str:
    """Stable hash of advertised tool names + descriptions + schema property keys
    (+ annotation hints, when a tool has any: 1.1.1)."""
    payload = []
    for tool in tools:
        schema = tool.input_schema or {}
        props = schema.get("properties") if isinstance(schema, dict) else None
        prop_keys = sorted(props.keys()) if isinstance(props, dict) else []
        entry = {
            "name": str(tool.name or ""),
            "description": str(tool.description or ""),
            "props": prop_keys,
        }
        hints = getattr(tool, "annotations", None)
        if hints:
            # 1.1.1: annotations can change a classification, so a change to them is
            # drift. Only when present, so a surface without them hashes as in 1.1.0.
            entry["annotations"] = {k: bool(v) for k, v in sorted(dict(hints).items())}
        payload.append(entry)
    # Sorting the entries (not the inputs) keeps the hash independent of input
    # order even when a server advertises the same name twice.
    payload.sort(key=lambda e: (e["name"], e["description"], e["props"],
                                sorted((e.get("annotations") or {}).items())))
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class SurfaceDrift:
    ok: bool
    expected_fingerprint: str
    live_fingerprint: str
    added: list[str]
    removed: list[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "expected_fingerprint": self.expected_fingerprint,
            "live_fingerprint": self.live_fingerprint,
            "added": list(self.added),
            "removed": list(self.removed),
            "reason": self.reason,
        }


def detect_drift(
    report: ServerAuditReport | dict[str, Any],
    live_tools: Sequence[McpToolDescriptor],
) -> SurfaceDrift:
    """Compare a persisted audit report to a live tool list.

    ``ok`` is True only when the report carries a fingerprint and it equals the
    live one. A report without a fingerprint cannot prove the descriptions and
    schemas are unchanged, so it reports drift and the host should re-audit.
    """
    if isinstance(report, dict):
        expected_fp = str(report.get("surface_fingerprint") or "")
        audited_names = {
            str(t.get("name"))
            for t in (report.get("tools") or [])
            if isinstance(t, dict) and t.get("name")
        }
    else:
        expected_fp = report.surface_fingerprint or ""
        audited_names = {t.name for t in report.tools}

    live_fp = surface_fingerprint(live_tools)
    live_names = {t.name for t in live_tools}
    added = sorted(live_names - audited_names)
    removed = sorted(audited_names - live_names)

    if expected_fp and expected_fp == live_fp and not added and not removed:
        return SurfaceDrift(
            ok=True,
            expected_fingerprint=expected_fp,
            live_fingerprint=live_fp,
            added=[],
            removed=[],
            reason="Surface matches audited fingerprint.",
        )
    parts = []
    if not expected_fp:
        parts.append("no fingerprint on file")
    if added:
        parts.append(f"added={','.join(added)}")
    if removed:
        parts.append(f"removed={','.join(removed)}")
    if expected_fp and expected_fp != live_fp:
        parts.append("fingerprint mismatch")
    return SurfaceDrift(
        ok=False,
        expected_fingerprint=expected_fp,
        live_fingerprint=live_fp,
        added=added,
        removed=removed,
        reason="Surface drift: " + ("; ".join(parts) or "unknown"),
    )
