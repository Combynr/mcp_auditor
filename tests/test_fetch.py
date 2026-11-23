"""Live-fetch adapter tests.

The fake-SDK tests run everywhere (no ``mcp`` install needed): they put stand-in
modules in ``sys.modules``. The live tests start a real MCP server over stdio and
over HTTP and skip when the SDK (or uvicorn, for HTTP) is not installed.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket
import subprocess
import sys
import textwrap
import time
import types
from datetime import timedelta

import pytest

from mcp_auditor import (
    ClearanceLevel,
    McpServerTarget,
    audit_server,
    fetch_server_tools,
    serialize_tool_list,
)
from mcp_auditor import fetch


# --------------------------------------------------------------------------- fakes


class FakeSession:
    """Stands in for mcp.ClientSession; serves ``pages`` keyed by cursor."""

    pages: dict = {None: {"tools": [{"name": "search_items", "description": "read"}]}}
    calls: list = []

    def __init__(self, *streams):
        self.streams = streams

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def initialize(self):
        return None

    async def list_tools(self, cursor=None):
        FakeSession.calls.append(cursor)
        return FakeSession.pages[cursor]


def _install_fake_sdk(monkeypatch, *, modern: bool, seen: dict) -> None:
    mcp_mod = types.ModuleType("mcp")
    client_mod = types.ModuleType("mcp.client")
    http_mod = types.ModuleType("mcp.client.streamable_http")
    mcp_mod.ClientSession = FakeSession

    if modern:
        class FakeHttpClient:
            def __init__(self, headers=None):
                seen["client_headers"] = headers

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                seen["client_closed"] = True
                return False

        @contextlib.asynccontextmanager
        async def streamable_http_client(url, *, http_client=None):
            seen["url"], seen["http_client"] = url, http_client
            yield (None, None)

        http_mod.create_mcp_http_client = FakeHttpClient
        http_mod.streamable_http_client = streamable_http_client
    else:
        @contextlib.asynccontextmanager
        async def streamablehttp_client(url, **kwargs):
            seen["url"], seen["kwargs"] = url, kwargs
            yield (None, None, None)

        http_mod.streamablehttp_client = streamablehttp_client

    mcp_mod.client = client_mod
    client_mod.streamable_http = http_mod
    monkeypatch.setitem(sys.modules, "mcp", mcp_mod)
    monkeypatch.setitem(sys.modules, "mcp.client", client_mod)
    monkeypatch.setitem(sys.modules, "mcp.client.streamable_http", http_mod)
    monkeypatch.setattr(FakeSession, "calls", [])


def _http_target(**kw) -> McpServerTarget:
    return McpServerTarget(
        transport="http",
        server_url="https://mcp.example/mcp",
        headers={"Authorization": "Bearer t"},
        timeout_seconds=7,
        **kw,
    )


def test_http_enumeration_sends_the_target_headers_older_sdk(monkeypatch):
    """Older SDKs: headers reach the client and the timeout is a timedelta.

    Those SDKs read ``timeout.seconds``; a bare int crashed them.
    """
    seen: dict = {}
    _install_fake_sdk(monkeypatch, modern=False, seen=seen)
    tools = asyncio.run(fetch_server_tools(_http_target()))
    assert [tool.name for tool in tools] == ["search_items"]
    assert seen["url"] == "https://mcp.example/mcp"
    assert seen["kwargs"]["headers"] == {"Authorization": "Bearer t"}
    assert seen["kwargs"]["timeout"] == timedelta(seconds=7)


def test_http_enumeration_sends_the_target_headers_newer_sdk(monkeypatch):
    """Newer SDKs (no ``streamablehttp_client``): headers go on the HTTP client."""
    seen: dict = {}
    _install_fake_sdk(monkeypatch, modern=True, seen=seen)
    tools = asyncio.run(fetch_server_tools(_http_target()))
    assert [tool.name for tool in tools] == ["search_items"]
    assert seen["client_headers"] == {"Authorization": "Bearer t"}
    assert seen["http_client"] is not None
    assert seen["client_closed"] is True


def test_enumeration_follows_pagination(monkeypatch):
    seen: dict = {}
    _install_fake_sdk(monkeypatch, modern=True, seen=seen)
    monkeypatch.setattr(FakeSession, "pages", {
        None: {"tools": [{"name": "list_a"}], "nextCursor": "p2"},
        "p2": {"tools": [{"name": "delete_b"}], "nextCursor": None},
    })
    tools = asyncio.run(fetch_server_tools(_http_target()))
    assert [tool.name for tool in tools] == ["list_a", "delete_b"]
    assert FakeSession.calls == [None, "p2"]


def test_enumeration_refuses_a_cursor_loop(monkeypatch):
    seen: dict = {}
    _install_fake_sdk(monkeypatch, modern=True, seen=seen)
    monkeypatch.setattr(FakeSession, "pages", {
        None: {"tools": [{"name": "list_a"}], "nextCursor": "p2"},
        "p2": {"tools": [{"name": "list_b"}], "nextCursor": "p2"},
    })
    with pytest.raises(RuntimeError, match="cursor"):
        asyncio.run(fetch_server_tools(_http_target()))


def test_enumeration_refuses_endless_pages(monkeypatch):
    seen: dict = {}
    _install_fake_sdk(monkeypatch, modern=True, seen=seen)

    class Endless(dict):
        def __missing__(self, cursor):
            n = 0 if cursor is None else int(cursor) + 1
            return {"tools": [{"name": f"t{n}"}], "nextCursor": str(n)}

    monkeypatch.setattr(FakeSession, "pages", Endless())
    monkeypatch.setattr(fetch, "MAX_TOOL_PAGES", 5)
    with pytest.raises(RuntimeError, match="pages"):
        asyncio.run(fetch_server_tools(_http_target()))


def test_enumeration_times_out(monkeypatch):
    seen: dict = {}
    _install_fake_sdk(monkeypatch, modern=True, seen=seen)

    async def hang(self, cursor=None):
        await asyncio.sleep(30)

    monkeypatch.setattr(FakeSession, "list_tools", hang)
    target = McpServerTarget(transport="http", server_url="https://x/mcp", timeout_seconds=0.2)
    with pytest.raises(TimeoutError):
        asyncio.run(fetch_server_tools(target))


def test_missing_sdk_raises_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "mcp", None)
    with pytest.raises(ImportError, match="fetch' extra"):
        asyncio.run(fetch_server_tools(_http_target()))


@pytest.mark.parametrize(
    "target, message",
    [
        (McpServerTarget(transport="stdio"), "command"),
        (McpServerTarget(transport="http"), "server_url"),
        (McpServerTarget(transport="carrier-pigeon"), "unsupported"),
    ],
)
def test_bad_targets_raise(target, message):
    with pytest.raises(ValueError, match=message):
        asyncio.run(fetch_server_tools(target))


def test_serialize_tool_list_handles_objects_dicts_and_drops_nameless():
    obj = types.SimpleNamespace(
        name="get_x", description=None, inputSchema={"properties": {"id": {}}}
    )
    response = types.SimpleNamespace(tools=[obj, {"name": "", "description": "x"}, {"name": "put_y"}])
    tools = serialize_tool_list(response)
    assert [t.name for t in tools] == ["get_x", "put_y"]
    assert tools[0].description == ""
    assert tools[0].input_schema == {"properties": {"id": {}}}
    assert serialize_tool_list({"tools": None}) == []


def test_audit_server_classifies_the_fetched_surface(monkeypatch):
    async def fake_fetch(target):
        return serialize_tool_list({"tools": [{"name": "list_a"}, {"name": "delete_b"}]})

    monkeypatch.setattr(fetch, "fetch_server_tools", fake_fetch)
    report = asyncio.run(audit_server(_http_target(), use_overseer=False))
    assert report.tool_count == 2
    assert report.recommended_clearance is ClearanceLevel.DRAFT_ONLY


# ---------------------------------------------------------------- real servers

_SERVER = textwrap.dedent(
    '''
    import sys
    try:
        from mcp.server import MCPServer as Server  # SDK 2.x
    except ImportError:
        from mcp.server.fastmcp import FastMCP as Server  # SDK 1.x

    app = Server("demo")

    @app.tool()
    def list_issues(repo: str) -> str:
        """List issues in a repository."""
        return "[]"

    @app.tool()
    def delete_repo(repo: str) -> str:
        """Delete a repository."""
        return "no"

    if sys.argv[1:2] == ["http"]:
        import uvicorn
        inner = app.streamable_http_app()

        async def guarded(scope, receive, send):
            # Refuse requests without the token, so the test proves headers arrive.
            if scope["type"] == "http":
                headers = dict(scope.get("headers") or [])
                if headers.get(b"authorization") != b"Bearer s3cret":
                    await send({"type": "http.response.start", "status": 401, "headers": []})
                    await send({"type": "http.response.body", "body": b"unauthorized"})
                    return
            await inner(scope, receive, send)

        uvicorn.run(guarded, host="127.0.0.1", port=int(sys.argv[2]), log_level="warning")
    else:
        app.run(transport="stdio")
    '''
)


@pytest.fixture
def server_script(tmp_path):
    pytest.importorskip("mcp")
    path = tmp_path / "demo_server.py"
    path.write_text(_SERVER)
    return path


def test_live_stdio_enumeration(server_script):
    target = McpServerTarget(
        transport="stdio", command=[sys.executable, str(server_script)], timeout_seconds=60
    )
    tools = asyncio.run(fetch_server_tools(target))
    assert sorted(t.name for t in tools) == ["delete_repo", "list_issues"]
    by_name = {t.name: t for t in tools}
    assert by_name["list_issues"].description == "List issues in a repository."
    assert "repo" in by_name["list_issues"].input_schema.get("properties", {})


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_live_http_enumeration_with_headers(server_script):
    pytest.importorskip("uvicorn")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(server_script), "http", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        url = f"http://127.0.0.1:{port}/mcp"
        good = McpServerTarget(
            transport="http", server_url=url,
            headers={"Authorization": "Bearer s3cret"}, timeout_seconds=30,
        )
        tools = asyncio.run(fetch_server_tools(good))
        assert sorted(t.name for t in tools) == ["delete_repo", "list_issues"]

        bad = McpServerTarget(transport="http", server_url=url, timeout_seconds=30)
        with pytest.raises(Exception):
            asyncio.run(fetch_server_tools(bad))
    finally:
        proc.terminate()
        proc.wait(timeout=10)
