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

# 1.1.1: state terms that are also nouns. Directly after a read verb that is the
# FIRST word of the tool's name ("get_schedule", "list_message_threads") such a term
# names the thing read, not an action. Only the name's own word is dropped; the
# description's state verbs always count (a server writes both, so "get_post" described
# as "post the draft publicly" stays a write).
AMBIGUOUS_STATE_NOUNS = frozenset({"schedule", "message", "email", "post", "run",
                                   "commit", "merge"})
# Narrower than DEFAULT_READ_ONLY_TERMS on purpose: "status_post", "explain_commit"
# and "check_schedule" are not reads of a post, commit or schedule.
READ_CONTEXT_VERBS = frozenset({"list", "get", "show", "read", "view", "describe",
                                "fetch", "search"})

# 1.1.1: words a trusted server's readOnlyHint never lowers. Outbound and side-effect
# verbs are where a mistaken or lying hint costs most (exfiltration, publication).
HINT_NEVER_LOWERS = frozenset({
    "send", "publish", "post", "email", "notify", "share", "delete", "create", "update",
    "write", "run", "merge", "commit", "message", "push", "deploy", "upload", "grant",
    "revoke", "invite", "approve", "trigger", "submit", "execute", "install", "uninstall",
    "transfer", "pay", "assign", "move", "rename", "archive", "restore", "cancel", "book",
    "schedule", "set", "add", "remove", "reply", "forward", "sync", "import", "export",
})

# 1.1.1: simple inflections. "posts", "posted", "committing" and "schedules" are the
# state word "post", "commit" or "schedule" (state words and HINT_NEVER_LOWERS only;
# destructive terms still match whole words). One suffix is stripped, then the stem is
# tried as is, with a final "e" ("scheduled") and with a doubled consonant undone
# ("committing", "stopped").
_INFLECTIONS = ("ing", "ed", "es", "s")


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
    # name heuristic calls state-changing to READ_ONLY. Destructive verbs, non-ASCII
    # names and HINT_NEVER_LOWERS words are never lowered. Untrusted (the default), a
    # server's annotations can only make a tool stricter (``destructiveHint: true``),
    # never more permissive.
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
    parts = _name_words(tool.name)
    nouns = _read_context_nouns(tool.name)
    # The noun is dropped by POSITION (the name's second word) only: a later copy of it
    # in the name, and every state word in the description, still count.
    name_words = parts[:1] + parts[2:] if nouns else parts
    state_hits = sorted(_inflected_hits(name_words, pol.state_changing_terms)
                        | _description_state_hits(tool.description, pol.state_changing_terms))
    hints = tool.annotations if isinstance(getattr(tool, "annotations", None), dict) else {}
    if hints.get("destructiveHint") is True and not destructive_hits:
        # Stricter is always allowed: a server saying its tool is destructive is heeded,
        # also when it says read-only too (contradictory hints get the stricter one).
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
            and hints.get("destructiveHint") is not True and name.isascii()
            and not _inflected_hits(tok, HINT_NEVER_LOWERS)):
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


def _name_words(name: object) -> list[str]:
    """The tool name's folded words, in order."""
    if not isinstance(name, str):
        return []
    return _TOKEN_PATTERN.findall(_fold(name))


def _base_forms(word: str) -> set[str]:
    forms = {word}
    for suffix in _INFLECTIONS:
        if word.endswith(suffix) and len(word) - len(suffix) >= 2:
            stem = word[: -len(suffix)]
            forms.update((stem, stem + "e"))
            if len(stem) >= 3 and stem[-1] == stem[-2]:
                forms.add(stem[:-1])
    return forms


def _inflected_hits(words, terms: frozenset[str]) -> set[str]:
    """The terms that the words are, or are a simple inflection of."""
    return {base for word in words for base in _base_forms(word) if base in terms}


def _description_state_hits(description: object, terms: frozenset[str]) -> set[str]:
    """State words in a description. An exact word always counts. An inflected form
    counts too ("then posts it"), except a plural-like form of an ambiguous noun right
    after a read verb ("Search messages", "Lists posts"): there it names what is read.
    That exception only ever narrows the inflection matching added in 1.1.1; 1.1.0
    matched whole words only."""
    if not isinstance(description, str):
        return set()
    words = _TOKEN_PATTERN.findall(_fold(description))
    hits: set[str] = set()
    for i, word in enumerate(words):
        if word in terms:
            hits.add(word)
            continue
        found = _inflected_hits((word,), terms)
        if i and found <= AMBIGUOUS_STATE_NOUNS \
                and _inflected_hits((words[i - 1],), READ_CONTEXT_VERBS):
            continue
        hits |= found
    return hits


def _read_context_nouns(name: object) -> set[str]:
    """The ambiguous noun a read-verb name reads ("schedule" in "get_schedule",
    "message" in "list_messages"), or an empty set. The name's first word must be a
    READ_CONTEXT_VERBS verb and its second word the noun (or an inflection of it). Only
    that position is dropped; a later copy of the noun in the name still counts."""
    if not isinstance(name, str) or not name.isascii():
        return set()
    parts = _name_words(name)
    if len(parts) < 2 or parts[0] not in READ_CONTEXT_VERBS:
        return set()
    return _inflected_hits(parts[1:2], AMBIGUOUS_STATE_NOUNS)


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
