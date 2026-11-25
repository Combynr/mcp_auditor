"""Optional MCP transport adapters (requires the official `mcp` Python SDK).

Install the ``fetch`` extra (or ``pip install "mcp>=1.8"``). Tested against the
1.x and 2.x SDK lines; their HTTP client APIs differ, so both are handled here.
"""
from __future__ import annotations

import asyncio
import contextlib
import inspect
from datetime import timedelta
from typing import Any

from .audit import audit_tool_surface
from .classify import ClassificationPolicy
from .overseer import OverseerFn
from .types import normalize_annotations, McpServerTarget, McpToolDescriptor, ServerAuditReport

# A server that keeps handing out cursors must not keep the audit running forever.
MAX_TOOL_PAGES = 100


async def fetch_server_tools(target: McpServerTarget) -> list[McpToolDescriptor]:
    """Connect to an MCP server and enumerate every advertised tool (all pages).

    ``target.timeout_seconds`` bounds the whole enumeration, for both transports;
    on expiry ``TimeoutError`` is raised. Nothing is returned on partial failure.
    """
    if target.transport == "stdio":
        if not target.command:
            raise ValueError("stdio MCP target requires a command")
        lister = _list_stdio_tools
    elif target.transport == "http":
        if not target.server_url:
            raise ValueError("http MCP target requires a server_url")
        lister = _list_http_tools
    else:
        raise ValueError(f"unsupported MCP transport: {target.transport!r}")
    try:
        import mcp  # noqa: F401
    except ImportError as error:
        raise ImportError(
            "live MCP enumeration needs the MCP SDK: install the 'fetch' extra "
            "or run: pip install \"mcp>=1.8\""
        ) from error
    try:
        return await asyncio.wait_for(lister(target), timeout=target.timeout_seconds)
    except asyncio.TimeoutError as error:
        raise TimeoutError(
            f"MCP tool enumeration exceeded {target.timeout_seconds} seconds"
        ) from error


async def _list_stdio_tools(target: McpServerTarget) -> list[McpToolDescriptor]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=target.command[0],
        args=target.command[1:],
        env=target.env,
    )
    async with stdio_client(params) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            return await _list_all_tools(session)


async def _list_http_tools(target: McpServerTarget) -> list[McpToolDescriptor]:
    from mcp import ClientSession
    import mcp.client.streamable_http as streamable_http

    modern = getattr(streamable_http, "streamable_http_client", None)
    make_client = getattr(streamable_http, "create_mcp_http_client", None)
    async with contextlib.AsyncExitStack() as stack:
        if modern is not None and make_client is not None:
            # Newer SDKs take headers through a caller-built HTTP client.
            http_client = await stack.enter_async_context(
                make_client(headers=target.headers)
            )
            streams = await stack.enter_async_context(
                modern(target.server_url, http_client=http_client)
            )
        else:
            legacy = streamable_http.streamablehttp_client
            streams = await stack.enter_async_context(
                legacy(
                    target.server_url,
                    headers=target.headers,
                    # Older SDKs read ``timeout.seconds``; a bare int crashes them.
                    timeout=timedelta(seconds=target.timeout_seconds),
                )
            )
        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        await session.initialize()
        return await _list_all_tools(session)


async def _list_all_tools(session: Any) -> list[McpToolDescriptor]:
    """Follow ``tools/list`` pagination so the audit sees the whole surface."""
    descriptors: list[McpToolDescriptor] = []
    seen_cursors: set[str] = set()
    response = await session.list_tools()
    for _ in range(MAX_TOOL_PAGES):
        descriptors.extend(serialize_tool_list(response))
        cursor = _next_cursor(response)
        if not cursor:
            return descriptors
        if cursor in seen_cursors:
            raise RuntimeError("MCP server repeated a tools/list cursor; refusing a partial audit")
        seen_cursors.add(cursor)
        response = await _list_tools_page(session, cursor)
    raise RuntimeError(
        f"MCP server returned more than {MAX_TOOL_PAGES} tools/list pages; "
        "refusing a partial audit"
    )


def _next_cursor(response: Any) -> str | None:
    if isinstance(response, dict):
        cursor = response.get("nextCursor") or response.get("next_cursor")
    else:
        cursor = getattr(response, "next_cursor", None) or getattr(response, "nextCursor", None)
    return cursor if isinstance(cursor, str) and cursor else None


async def _list_tools_page(session: Any, cursor: str) -> Any:
    parameters = inspect.signature(session.list_tools).parameters
    if "params" in parameters:
        from mcp.types import PaginatedRequestParams

        return await session.list_tools(params=PaginatedRequestParams(cursor=cursor))
    return await session.list_tools(cursor=cursor)


def serialize_tool_list(response: Any) -> list[McpToolDescriptor]:
    """Convert an SDK ``ListToolsResult`` (or a plain dict) into descriptors.

    Entries without a name are dropped: a call has to name the tool, so an
    unnamed entry cannot be invoked.
    """
    raw_tools = getattr(response, "tools", None)
    if raw_tools is None and isinstance(response, dict):
        raw_tools = response.get("tools")
    descriptors: list[McpToolDescriptor] = []
    for tool in raw_tools or []:
        name = getattr(tool, "name", None)
        description = getattr(tool, "description", None)
        schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
        annotations = getattr(tool, "annotations", None)
        if name is None and isinstance(tool, dict):
            name = tool.get("name")
            description = tool.get("description")
            schema = tool.get("inputSchema") or tool.get("input_schema")
            annotations = tool.get("annotations")
        if not name:
            continue
        descriptors.append(
            McpToolDescriptor(
                name=str(name),
                description=str(description or ""),
                input_schema=schema if isinstance(schema, dict) else {},
                annotations=normalize_annotations(annotations),
            )
        )
    return descriptors


async def audit_server(
    target: McpServerTarget,
    *,
    overseer: OverseerFn | None = None,
    use_overseer: bool = True,
    policy: ClassificationPolicy | None = None,
) -> ServerAuditReport:
    """Full audit: fetch the live tool surface, then classify (+ optional Overseer)."""
    tools = await fetch_server_tools(target)
    return await audit_tool_surface(
        tools, overseer=overseer, use_overseer=use_overseer, policy=policy
    )
