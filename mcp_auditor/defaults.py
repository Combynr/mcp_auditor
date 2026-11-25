"""Built-in argument rules for the high-risk families, used when nothing is declared.

A host that never writes a schema still gets these whenever a call is detected as a
file write, shell, email, outbound HTTP or office write-back call (see
:mod:`mcp_auditor.families`). They are written to be safe without knowing the
server: they check the arguments a family is recognised by, wherever they appear,
and leave every other argument alone, so ordinary calls to common servers pass.

Each check ends in one of three ways:

* **block**: clearly malformed or hostile (a ``..`` path, a ``file:`` URL, a header
  injected into a recipient, a write far over a size cap);
* **hold**: plausible but needs a person (anything that writes, runs or sends, and
  HTTP to a private or loopback host);
* **pass**: the call keeps its clearance (HTTP to a public host).

A schema declared for a tool's own name replaces these defaults for that tool.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from email.utils import getaddresses
from typing import Any, Mapping
from urllib.parse import urlsplit

from .arguments import path_problem
from .families import (
    _CONTENT_KEYS,
    _EMAIL_KEYS,
    _HTTP_KEYS,
    _OFFICE_KEYS,
    _PATH_KEYS,
    _SHELL_KEYS,
    EMAIL,
    FILE_WRITE,
    HTTP,
    OFFICE_WRITE,
    SHELL,
)

MAX_WRITE_BYTES = 10_000_000
MAX_COMMAND_CHARS = 8_000
MAX_ARGV_ITEMS = 256
MAX_RECIPIENTS = 50
MAX_MESSAGE_BYTES = 1_000_000
MAX_URL_CHARS = 8_192
MAX_URLS = 20
MAX_OFFICE_ROWS = 10_000
MAX_OFFICE_CELLS = 200_000
MAX_PATHS = 100

_EXTRA_PATH_KEYS = frozenset({"source", "target", "new_path", "old_path", "src", "dst"})
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")


@dataclass(frozen=True)
class FamilyDefault:
    family: str
    hold: bool
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {"family": self.family, "hold": self.hold, "summary": self.summary}


DEFAULT_PACK: dict[str, FamilyDefault] = {
    FILE_WRITE: FamilyDefault(
        FILE_WRITE, True,
        "Held for approval. Paths must be strings without '..' or NUL and, when a "
        f"workspace root is set, resolve inside it; at most {MAX_PATHS} paths and "
        f"{MAX_WRITE_BYTES:,} bytes of content."),
    SHELL: FamilyDefault(
        SHELL, True,
        f"Held for approval. Commands are strings of at most {MAX_COMMAND_CHARS:,} "
        f"characters (or at most {MAX_ARGV_ITEMS} string arguments), without NUL."),
    EMAIL: FamilyDefault(
        EMAIL, True,
        "Held for approval. Each recipient is one address without line breaks; at most "
        f"{MAX_RECIPIENTS} recipients and {MAX_MESSAGE_BYTES:,} bytes of message."),
    HTTP: FamilyDefault(
        HTTP, False,
        "http or https only, no credentials in the URL, at most "
        f"{MAX_URL_CHARS:,} characters and {MAX_URLS} URLs. A private, loopback or "
        "local host is held for approval; a public host keeps the tool's clearance."),
    OFFICE_WRITE: FamilyDefault(
        OFFICE_WRITE, True,
        f"Held for approval. At most {MAX_OFFICE_ROWS:,} rows and "
        f"{MAX_OFFICE_CELLS:,} cells of values, and {MAX_MESSAGE_BYTES * 5:,} bytes of "
        "content."),
}


def describe_defaults() -> list[dict[str, Any]]:
    """The default pack in plain words, for a settings screen."""
    return [DEFAULT_PACK[f].to_dict() for f in sorted(DEFAULT_PACK)]


def check_defaults(
    families: frozenset[str], arguments: Any, *, workspace_root: str | None = None,
) -> tuple[list[str], list[str]]:
    """(reasons to block, reasons to hold) under the default pack."""
    blocks: list[str] = []
    holds: list[str] = []
    args = _flat(arguments)
    for family in sorted(families):
        default = DEFAULT_PACK.get(family)
        if default is None:
            continue
        if default.hold:
            holds.append(f"{family} calls wait for approval by default")
        checker = _CHECKERS[family]
        checker(args, workspace_root, blocks, holds)
    return blocks, holds


def _flat(arguments: Any) -> dict[str, list[Any]]:
    """Every value under each lower-cased key, nested mappings included (bounded)."""
    out: dict[str, list[Any]] = {}

    def walk(value: Any, depth: int) -> None:
        if depth > 4:
            return
        if isinstance(value, Mapping):
            for key, item in list(value.items())[:256]:
                if isinstance(key, str):
                    out.setdefault(key.strip().casefold(), []).append(item)
                walk(item, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value[:256]:
                if isinstance(item, (Mapping, list, tuple)):
                    walk(item, depth + 1)

    walk(arguments, 0)
    return out


def _strings(value: Any, limit: int) -> list[str] | None:
    """A string or a list of strings as a list; None for anything else."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and len(value) <= limit \
            and all(isinstance(v, str) for v in value):
        return list(value)
    return None


def _size(value: Any) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return MAX_WRITE_BYTES + 1


def _file(args, root, blocks, holds) -> None:
    for key in sorted(set(args) & (_PATH_KEYS | _EXTRA_PATH_KEYS)):
        for value in args[key]:
            if value is None:
                continue
            paths = _strings(value, MAX_PATHS)
            if paths is None:
                blocks.append(f"'{key}' must be a path or a list of at most {MAX_PATHS} paths")
                continue
            for path in paths:
                why = _default_path_problem(path, root)
                if why:
                    blocks.append(f"'{key}' {why}")
    for key in sorted(set(args) & _CONTENT_KEYS):
        if any(_size(v) > MAX_WRITE_BYTES for v in args[key]):
            blocks.append(f"'{key}' is larger than {MAX_WRITE_BYTES:,} bytes")


def _default_path_problem(path: str, root: str | None) -> str:
    if "\x00" in path:
        return "contains a NUL character"
    parts = path.replace("\\", "/").split("/")
    if ".." in parts:
        return "climbs out of its folder with '..'"
    if root:
        return path_problem(path, root)
    return ""


def _shell(args, root, blocks, holds) -> None:
    for key in sorted(set(args) & _SHELL_KEYS):
        for value in args[key]:
            parts = _strings(value, MAX_ARGV_ITEMS)
            if parts is None:
                blocks.append(f"'{key}' must be a command string or a list of strings")
            elif any("\x00" in p or len(p) > MAX_COMMAND_CHARS for p in parts):
                blocks.append(f"'{key}' is longer than {MAX_COMMAND_CHARS:,} characters "
                              "or contains NUL")


def _email(args, root, blocks, holds) -> None:
    count = 0
    for key in sorted(set(args) & _EMAIL_KEYS):
        for value in args[key]:
            if value is None:
                continue
            entries = _strings(value, 10 * MAX_RECIPIENTS)
            if entries is None:
                blocks.append(f"'{key}' must be an address or a list of addresses")
                continue
            for entry in entries:
                if any(c in entry for c in "\r\n\x00"):
                    blocks.append(f"'{key}' contains a line break (header injection)")
                    continue
                for _name, address in getaddresses([entry]):
                    count += 1
                    local, _, domain = address.rpartition("@")
                    if not local or "." not in domain or " " in address:
                        blocks.append(f"'{key}' has an address that is not valid")
    if count > MAX_RECIPIENTS:
        blocks.append(f"more than {MAX_RECIPIENTS} recipients")
    for key in sorted(set(args) & (_CONTENT_KEYS | {"subject", "html", "message"})):
        if any(_size(v) > MAX_MESSAGE_BYTES for v in args[key]):
            blocks.append(f"'{key}' is larger than {MAX_MESSAGE_BYTES:,} bytes")


def _http(args, root, blocks, holds) -> None:
    for key in sorted(set(args) & _HTTP_KEYS):
        for value in args[key]:
            if value is None:
                continue
            urls = _strings(value, MAX_URLS)
            if urls is None:
                blocks.append(f"'{key}' must be a URL or a list of at most {MAX_URLS} URLs")
                continue
            for url in urls:
                verdict = _url_verdict(url)
                if verdict.startswith("block:"):
                    blocks.append(f"'{key}' {verdict[6:]}")
                elif verdict.startswith("hold:"):
                    holds.append(f"'{key}' {verdict[5:]}")


def _url_verdict(url: str) -> str:
    if len(url) > MAX_URL_CHARS or any(c in url for c in "\r\n\x00"):
        return "block:is too long or contains control characters"
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return "block:is not a valid URL"
    if parts.scheme.lower() not in {"http", "https"}:
        return "block:must be an http or https URL"
    if parts.username is not None or parts.password is not None:
        return "block:must not carry credentials"
    if not host:
        return "block:must name a host"
    if host == "localhost" or host.endswith(_LOCAL_SUFFIXES) or "." not in host.strip("[]"):
        return "hold:points at a local host"
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return ""
    if not address.is_global:
        return "hold:points at a private, loopback or link-local address"
    return ""


def _office(args, root, blocks, holds) -> None:
    for key in sorted(set(args) & (_OFFICE_KEYS & {"values", "formulas", "cells"})):
        for value in args[key]:
            if not isinstance(value, (list, tuple)):
                continue
            rows = len(value)
            cells = sum(len(r) if isinstance(r, (list, tuple)) else 1 for r in value)
            if rows > MAX_OFFICE_ROWS or cells > MAX_OFFICE_CELLS:
                blocks.append(f"'{key}' is over {MAX_OFFICE_ROWS:,} rows or "
                              f"{MAX_OFFICE_CELLS:,} cells")
    for key in sorted(set(args) & _CONTENT_KEYS):
        if any(_size(v) > MAX_MESSAGE_BYTES * 5 for v in args[key]):
            blocks.append(f"'{key}' is larger than {MAX_MESSAGE_BYTES * 5:,} bytes")


_CHECKERS = {FILE_WRITE: _file, SHELL: _shell, EMAIL: _email, HTTP: _http,
             OFFICE_WRITE: _office}
