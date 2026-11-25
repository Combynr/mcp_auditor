"""Deterministic blast-radius classification for MCP tool descriptors."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Sequence

from .types import ClearanceLevel, McpToolDescriptor, ToolRisk, max_clearance

# Word-boundary token matching keeps "list_orders" READ_ONLY while flagging
# "delete_order" / "create_order" as mutating.

DEFAULT_DESTRUCTIVE_TERMS = frozenset(
    {
        "delete", "drop", "truncate", "wipe", "destroy", "remove", "purge", "erase",
        "unlink", "revoke", "terminate", "kill", "format", "deprovision", "uninstall",
        "transfer", "withdraw", "pay", "payment", "refund", "charge", "wire",
        "sudo", "exec", "execute", "shell", "eval", "spawn", "rmdir", "rm",
        "force", "reset", "overwrite", "rollback", "shutdown", "reboot",
        # "send" alone is too noisy (send_notification); keep money/exfil verbs.
        "exfiltrate", "exfil",
    }
)

DEFAULT_STATE_CHANGING_TERMS = frozenset(
    {
        "create", "update", "write", "set", "put", "post", "patch", "insert", "upsert",
        "modify", "edit", "move", "rename", "append", "email", "message", "publish",
        "push", "commit", "merge", "approve", "assign", "schedule", "upload", "install",
        "enable", "disable", "configure", "grant", "add", "register", "provision",
        "deploy", "invite", "subscribe", "trigger", "run", "start", "stop", "restart",
        "send",  # outbound side-effect; HITL by default
    }
)

DEFAULT_READ_ONLY_TERMS = frozenset(
    {
        "get", "list", "read", "search", "query", "fetch", "find", "view", "show",
        "describe", "lookup", "count", "status", "health", "info", "retrieve",
        "inspect", "preview", "summarize", "explain", "analyze", "check",
    }
)

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")

# 1.1.1: state terms that are also nouns. After a leading read verb in the tool's
# name ("get_schedule", "list_message_threads") such a term names the thing read,
# not an action. Only these, only after a read verb that starts the name, and never
# in a name that joins actions ("get_and_schedule").
AMBIGUOUS_STATE_NOUNS = frozenset({"schedule", "message", "email", "post", "run",
                                   "commit", "merge"})
_JOINERS = frozenset({"and", "then", "or", "to", "plus"})


def _fold(text: str) -> str:
    # NFKC folds compatibility forms (fullwidth "ＤＥＬＥＴＥ") onto ASCII before
    # matching; homoglyphs from other scripts are not folded (see classify_tool).
    return unicodedata.normalize("NFKC", text).casefold()


def tokens(*texts: str) -> set[str]:
    """Lowercase alphanumeric word tokens of the given texts."""
    bucket: set[str] = set()
    for text in texts:
        if not text or not isinstance(text, str):
            continue
        bucket.update(_TOKEN_PATTERN.findall(_fold(text)))
    return bucket


def _terms(values: Sequence[str] | None) -> frozenset[str]:
    # Tokens are folded to lowercase, so extra terms must be too or they never match.
    return frozenset(_fold(v) for v in (values or ()) if isinstance(v, str))


@dataclass
class ClassificationPolicy:
    """Optional host-tunable verb sets (defaults are fail-closed for mutations)."""

    destructive_terms: frozenset[str] = DEFAULT_DESTRUCTIVE_TERMS
    state_changing_terms: frozenset[str] = DEFAULT_STATE_CHANGING_TERMS
    read_only_terms: frozenset[str] = DEFAULT_READ_ONLY_TERMS
    empty_surface_clearance: ClearanceLevel = ClearanceLevel.DRAFT_ONLY
    # If True, destructive tools raise server floor to BLOCKED (strict mode).
    block_destructive: bool = False
    # 1.1.1: set ONLY for a server an administrator marked trusted. Then its
    # ``readOnlyHint: true`` (without ``destructiveHint: true``) may lower a tool the
    # name heuristic calls state-changing to READ_ONLY. Destructive verbs and non-ASCII
    # names are never lowered. Untrusted (the default), a server's annotations can only
    # make a tool stricter (``destructiveHint: true``), never more permissive.
    trust_annotations: bool = False

    def __post_init__(self) -> None:
        self.destructive_terms = _terms(self.destructive_terms)
        self.state_changing_terms = _terms(self.state_changing_terms)
        self.read_only_terms = _terms(self.read_only_terms)

    def with_extra(
        self,
        *,
        destructive: Sequence[str] | None = None,
        state_changing: Sequence[str] | None = None,
        read_only: Sequence[str] | None = None,
    ) -> ClassificationPolicy:
        return ClassificationPolicy(
            destructive_terms=self.destructive_terms | _terms(destructive),
            state_changing_terms=self.state_changing_terms | _terms(state_changing),
            read_only_terms=self.read_only_terms | _terms(read_only),
            empty_surface_clearance=self.empty_surface_clearance,
            block_destructive=self.block_destructive,
            trust_annotations=self.trust_annotations,
        )


DEFAULT_POLICY = ClassificationPolicy()


def classify_tool(
    tool: McpToolDescriptor,
    policy: ClassificationPolicy | None = None,
) -> ToolRisk:
    pol = policy or DEFAULT_POLICY
    tok = tokens(tool.name, tool.description)
    destructive_hits = sorted(tok & pol.destructive_terms)
    state_hits = sorted(tok & pol.state_changing_terms)
    nouns = _read_context_nouns(tool.name, pol)
    if nouns:
        state_hits = [hit for hit in state_hits if hit not in nouns]
    hints = tool.annotations if isinstance(getattr(tool, "annotations", None), dict) else {}
    if hints.get("destructiveHint") is True and hints.get("readOnlyHint") is not True \
            and not destructive_hits:
        # Stricter is always allowed: a server saying its tool is destructive is heeded.
        destructive_hits = ["destructiveHint annotation"]

    if destructive_hits:
        clearance = (
            ClearanceLevel.BLOCKED if pol.block_destructive else ClearanceLevel.DRAFT_ONLY
        )
        return ToolRisk(
            name=tool.name,
            category="destructive",
            clearance=clearance,
            signals=[hit if " " in hit else f"destructive verb: {hit}"
                     for hit in destructive_hits],
            description=tool.description,
        )
    name = tool.name if isinstance(tool.name, str) else ""
    if (pol.trust_annotations and hints.get("readOnlyHint") is True
            and hints.get("destructiveHint") is not True and name.isascii()):
        return ToolRisk(
            name=tool.name,
            category="read_only",
            clearance=ClearanceLevel.READ_ONLY,
            signals=["readOnlyHint from a server an administrator marked trusted"]
            + [f"state-changing verb overridden by it: {hit}" for hit in state_hits],
            description=tool.description,
        )
    if state_hits:
        return ToolRisk(
            name=tool.name,
            category="state_changing",
            clearance=ClearanceLevel.DRAFT_ONLY,
            signals=[f"state-changing verb: {hit}" for hit in state_hits],
            description=tool.description,
        )
    if not name.isascii():
        # Non-ASCII letters in a name can hide a verb from the token matcher
        # (Cyrillic "е" in "dеlete"), so such a name never earns READ_ONLY.
        return ToolRisk(
            name=tool.name,
            category="state_changing",
            clearance=ClearanceLevel.DRAFT_ONLY,
            signals=["non-ASCII characters in tool name; defaulting to human review"],
            description=tool.description,
        )
    read_hits = sorted(tok & pol.read_only_terms)
    if read_hits:
        return ToolRisk(
            name=tool.name,
            category="read_only",
            clearance=ClearanceLevel.READ_ONLY,
            signals=[f"read-only verb: {hit}" for hit in read_hits]
            + [f"read context: '{n}' names what is read" for n in sorted(nouns)],
            description=tool.description,
        )
    # Unknown verbs are NOT treated as read-only — that was a false-negative
    # hole (e.g. customer_sync / blob_handoff). Fail closed to human review.
    return ToolRisk(
        name=tool.name,
        category="state_changing",
        clearance=ClearanceLevel.DRAFT_ONLY,
        signals=["no recognised verb; defaulting to human review"],
        description=tool.description,
    )


def _read_context_nouns(name: object, pol: ClassificationPolicy) -> set[str]:
    """The ambiguous state nouns a read-verb name reads ("schedule" in
    "get_schedule"), or an empty set. The name must start with a read verb and not
    join actions; the noun must appear in the name itself."""
    if not isinstance(name, str) or not name.isascii():
        return set()
    parts = _TOKEN_PATTERN.findall(_fold(name))
    if len(parts) < 2 or parts[0] not in pol.read_only_terms or _JOINERS & set(parts):
        return set()
    return {p for p in parts[1:] if p in AMBIGUOUS_STATE_NOUNS}


def classify_tools(
    tools: Sequence[McpToolDescriptor],
    policy: ClassificationPolicy | None = None,
) -> list[ToolRisk]:
    return [classify_tool(tool, policy) for tool in tools]


def static_clearance(
    tool_risks: Sequence[ToolRisk],
    policy: ClassificationPolicy | None = None,
) -> ClearanceLevel:
    pol = policy or DEFAULT_POLICY
    if not tool_risks:
        return pol.empty_surface_clearance
    return max_clearance(*(risk.clearance for risk in tool_risks))
