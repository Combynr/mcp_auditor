"""Surface fingerprint and drift detection."""
from __future__ import annotations

from mcp_auditor import McpToolDescriptor, audit_tool_surface_sync, detect_drift, surface_fingerprint

BASE = [
    McpToolDescriptor(name="get_x", description="Get x", input_schema={"properties": {"id": {}}}),
    McpToolDescriptor(name="put_x", description="Put x"),
]


def test_fingerprint_changes_with_name_description_and_schema_keys():
    fp = surface_fingerprint(BASE)
    assert fp == surface_fingerprint(list(reversed(BASE)))
    renamed = [McpToolDescriptor(name="get_y", description="Get x", input_schema=BASE[0].input_schema), BASE[1]]
    redescribed = [McpToolDescriptor(name="get_x", description="Get x and delete", input_schema=BASE[0].input_schema), BASE[1]]
    new_param = [McpToolDescriptor(name="get_x", description="Get x",
                                   input_schema={"properties": {"id": {}, "cmd": {}}}), BASE[1]]
    assert len({fp, surface_fingerprint(renamed), surface_fingerprint(redescribed),
                surface_fingerprint(new_param)}) == 4


def test_fingerprint_is_order_independent_with_duplicate_names_and_none():
    a = McpToolDescriptor(name="x", description="one")
    b = McpToolDescriptor(name="x", description="two")
    assert surface_fingerprint([a, b]) == surface_fingerprint([b, a])
    nameless = McpToolDescriptor(name=None)  # type: ignore[arg-type]
    assert surface_fingerprint([nameless, a]) == surface_fingerprint([a, nameless])


def test_drift_ok_and_detected():
    report = audit_tool_surface_sync(BASE)
    assert detect_drift(report, BASE).ok
    assert detect_drift(report.to_dict(), BASE).ok

    added = detect_drift(report, BASE + [McpToolDescriptor(name="evil")])
    assert not added.ok and added.added == ["evil"]
    removed = detect_drift(report, BASE[:1])
    assert not removed.ok and removed.removed == ["put_x"]
    changed = detect_drift(report, [McpToolDescriptor(name="get_x", description="now deletes"), BASE[1]])
    assert not changed.ok and "fingerprint mismatch" in changed.reason
    assert changed.to_dict()["ok"] is False


def test_report_without_fingerprint_is_drift():
    """Bug: a report with no fingerprint passed as long as the names matched."""
    data = audit_tool_surface_sync(BASE).to_dict()
    data["surface_fingerprint"] = ""
    drift = detect_drift(data, [McpToolDescriptor(name="get_x", description="rm -rf"), BASE[1]])
    assert not drift.ok
    assert "no fingerprint" in drift.reason
