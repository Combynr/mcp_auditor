"""Static classifier."""
from __future__ import annotations

import pytest

from mcp_auditor import (
    ClassificationPolicy,
    ClearanceLevel,
    McpToolDescriptor,
    classify_tool,
    classify_tools,
    static_clearance,
    tokens,
)

R, D, B = ClearanceLevel.READ_ONLY, ClearanceLevel.DRAFT_ONLY, ClearanceLevel.BLOCKED


def _c(name, description="", policy=None):
    return classify_tool(McpToolDescriptor(name=name, description=description), policy)


@pytest.mark.parametrize(
    "name, description, category, clearance",
    [
        ("list_orders", "", "read_only", R),
        ("get-record", "", "read_only", R),
        ("create_invoice", "", "state_changing", D),
        ("delete_customer", "", "destructive", D),
        ("list_and_delete", "", "destructive", D),
        ("lookup", "Look up a user, then wipe their data", "destructive", D),
        ("customer_sync", "", "state_changing", D),
        ("", "", "state_changing", D),
    ],
)
def test_categories(name, description, category, clearance):
    risk = _c(name, description)
    assert (risk.category, risk.clearance) == (category, clearance)
    assert risk.signals


def test_block_destructive_mode():
    assert _c("drop_table", policy=ClassificationPolicy(block_destructive=True)).clearance is B


def test_extra_terms_are_case_folded():
    """Bug: uppercase extra terms never matched the lowercased tokens."""
    strict = ClassificationPolicy(block_destructive=True).with_extra(destructive=["Nuke"])
    assert _c("nuke_db", policy=strict).clearance is B
    direct = ClassificationPolicy(destructive_terms=frozenset({"Zap"}), block_destructive=True)
    assert _c("zap_db", policy=direct).clearance is B
    assert _c("peek_x", policy=ClassificationPolicy().with_extra(read_only=["PEEK"])).clearance is R


def test_fullwidth_letters_are_folded():
    assert _c("list_ｄｅｌｅｔｅ").category == "destructive"


def test_homoglyph_in_name_never_reads_as_read_only():
    """Bug: "list_dеlete_all" with a Cyrillic е hid the destructive verb and read as READ_ONLY."""
    risk = _c("list_dеlete_all")
    assert risk.clearance is D
    assert "non-ASCII" in risk.signals[0]


def test_tokens():
    assert tokens("List_Orders", None, "", "x-y") == {"list", "orders", "x", "y"}


def test_static_clearance():
    assert static_clearance([]) is D
    assert static_clearance(classify_tools([McpToolDescriptor(name="get_x")])) is R
    risks = classify_tools([McpToolDescriptor(name="get_x"), McpToolDescriptor(name="put_x")])
    assert static_clearance(risks) is D
