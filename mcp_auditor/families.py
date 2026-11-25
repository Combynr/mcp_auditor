"""High-risk tool families, detected from more than the tool's name.

A family is a kind of side effect that must not run unattended without declared
argument rules: writing or deleting files, running shell commands, sending email,
making outbound HTTP requests and writing back to office documents.

Detection looks at the tool name, the description and the argument keys of the
call itself. The keys come from the caller and cannot be hidden by renaming the
tool, so ``save_note(path=..., content=...)`` is still a file write. Detection
only ever makes a call stricter; a false positive costs an approval, not a
breach.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable, Mapping

FILE_WRITE = "file_write"
SHELL = "shell"
EMAIL = "email"
HTTP = "http"
OFFICE_WRITE = "office_write"

HIGH_RISK_FAMILIES = (FILE_WRITE, SHELL, EMAIL, HTTP, OFFICE_WRITE)

_WRITE_VERBS = frozenset({
    "write", "save", "delete", "remove", "rm", "unlink", "move", "mv", "rename",
    "overwrite", "append", "upload", "put", "mkdir", "rmdir", "truncate", "chmod",
    "chown", "copy", "cp", "create", "update", "edit", "patch", "replace", "insert",
    "set", "modify", "erase", "wipe", "purge", "destroy",
})
_FILE_NOUNS = frozenset({"file", "files", "path", "paths", "dir", "directory", "folder", "fs"})
_PATH_KEYS = frozenset({
    "path", "paths", "file", "file_path", "filepath", "filename", "file_name", "dest",
    "destination", "target_path", "dir", "directory", "folder", "source_path",
})
_CONTENT_KEYS = frozenset({"content", "contents", "data", "text", "body", "bytes", "blob"})

_SHELL_TERMS = frozenset({
    "shell", "exec", "execute", "bash", "sh", "zsh", "powershell", "pwsh", "cmd",
    "terminal", "subprocess", "spawn", "eval", "command", "commands",
})
_SHELL_KEYS = frozenset({
    "command", "cmd", "commands", "script", "argv", "shell", "command_line",
    "commandline", "shell_command",
})

_EMAIL_TERMS = frozenset({"email", "mail", "smtp", "sendmail", "gmail", "outlook", "inbox"})
_EMAIL_KEYS = frozenset({
    "to", "cc", "bcc", "recipient", "recipients", "to_address", "to_addresses",
    "email_to", "send_to", "reply_to",
})

# Generic verbs such as "fetch" or "request" are left out: "fetch_issues" and
# "list_pull_requests" are ordinary reads. The argument keys catch the rest.
_HTTP_TERMS = frozenset({
    "http", "https", "url", "urls", "uri", "webhook", "curl", "wget", "browse", "navigate",
})
_HTTP_KEYS = frozenset({
    "url", "urls", "uri", "endpoint", "webhook", "webhook_url", "href", "link",
    "callback_url", "target_url",
})

_OFFICE_TERMS = frozenset({
    "excel", "workbook", "worksheet", "sheet", "sheets", "spreadsheet", "cell", "cells",
    "range", "word", "document", "docx", "xlsx", "pptx", "powerpoint", "slide",
    "slides", "onenote", "office",
})
_OFFICE_KEYS = frozenset({
    "workbook", "worksheet", "sheet", "sheet_name", "range", "range_address", "cell",
    "cells", "document_id", "slide", "slide_index", "values", "formulas",
})

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WORD = re.compile(r"[a-z0-9]+")
_MAX_KEY_DEPTH = 4


def family_tokens(*texts: str) -> set[str]:
    """Word tokens with camelCase split, so ``writeFile`` yields ``write`` and ``file``."""
    out: set[str] = set()
    for text in texts:
        if not isinstance(text, str) or not text:
            continue
        folded = unicodedata.normalize("NFKC", text)
        out.update(_WORD.findall(_CAMEL.sub(" ", folded).casefold()))
    return out


def argument_keys(arguments: Any, _depth: int = 0) -> set[str]:
    """Lower-cased keys of an argument mapping, nested mappings and lists included."""
    keys: set[str] = set()
    if _depth > _MAX_KEY_DEPTH:
        return keys
    if isinstance(arguments, Mapping):
        for key, value in arguments.items():
            if isinstance(key, str):
                keys.add(key.strip().casefold())
            keys |= argument_keys(value, _depth + 1)
    elif isinstance(arguments, (list, tuple)):
        for item in arguments[:64]:
            keys |= argument_keys(item, _depth + 1)
    return keys


def detect_families(
    tool_name: str,
    description: str = "",
    arguments: Any = None,
    schema_properties: Iterable[str] = (),
) -> frozenset[str]:
    """The high-risk families a call belongs to (empty when none apply)."""
    words = family_tokens(tool_name or "", description or "")
    keys = argument_keys(arguments) | {
        str(p).strip().casefold() for p in schema_properties if isinstance(p, str)
    }
    found: set[str] = set()
    writes = bool(words & _WRITE_VERBS)
    if writes and (words & _FILE_NOUNS or keys & _PATH_KEYS):
        found.add(FILE_WRITE)
    if keys & _PATH_KEYS and keys & _CONTENT_KEYS:
        found.add(FILE_WRITE)
    if words & _SHELL_TERMS or keys & _SHELL_KEYS:
        found.add(SHELL)
    if (words & _EMAIL_TERMS and (writes or words & {"send", "reply", "forward", "draft"})) \
            or keys & _EMAIL_KEYS:
        found.add(EMAIL)
    if words & _HTTP_TERMS or keys & _HTTP_KEYS:
        found.add(HTTP)
    if (words & _OFFICE_TERMS or keys & _OFFICE_KEYS) and (writes or keys & _CONTENT_KEYS
                                                           or "values" in keys):
        found.add(OFFICE_WRITE)
    return frozenset(found)
