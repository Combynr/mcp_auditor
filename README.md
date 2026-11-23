# mcp:auditor

mcp:auditor decides whether an AI agent may call a tool on a Model Context Protocol (MCP) server: it classifies the tools a server advertises, assigns a clearance, keeps an allowlist of servers, and returns `auto_approved`, `requires_approval` or `blocked` for each call. It is a small, framework-free Python library with no runtime dependencies; your application supplies persistence, the approval UI and, optionally, an LLM reviewer.

## Why

An agent connected to MCP servers can reach shells, payment APIs, email and cloud consoles through tools it discovers at run time. mcp:auditor gives the host application one place to decide, before each call, whether that call may run unattended, needs a human, or must be refused. Every path that is not explicitly allowed ends in `requires_approval` or `blocked`.

## Install

Python 3.10 or newer.

From GitHub:

```bash
pip install "mcp-auditor @ git+https://github.com/Combynr/mcp_auditor"
```

From a local clone:

```bash
git clone https://github.com/Combynr/mcp_auditor
cd mcp_auditor
pip install -e .            # add ".[dev]" for the test tools
```

The distribution is named `mcp-auditor` and the import name is `mcp_auditor`. This project is not published on PyPI. A different, unrelated project uses the name `mcp-auditor` there, so `pip install mcp-auditor` does not install this library.

## Quick start

```python
from mcp_auditor import (
    AllowlistPolicy, AllowlistedServer, ClearanceLevel,
    McpToolDescriptor, audit_tool_surface_sync, surface_fingerprint,
)

# The tools a server advertises (from tools/list, or built by hand).
tools = [
    McpToolDescriptor(name="list_issues", description="List issues in a repository"),
    McpToolDescriptor(name="create_issue", description="Create an issue"),
]

# 1. Audit the surface. Without an overseer this is static classification only.
report = audit_tool_surface_sync(tools)
print(report.summary)
assert report.recommended_clearance is ClearanceLevel.DRAFT_ONLY

# 2. Put the server on the allowlist. Persist policy.to_dict() however you like.
policy = AllowlistPolicy(enabled=True)
policy.upsert(AllowlistedServer(
    server_id="issues",
    clearance=report.recommended_clearance,
    audit_report=report.to_dict(),
))

# 3. Ask before every call.
decision = policy.evaluate(
    server_id="issues",
    tool_name="create_issue",
    execution_mode="AUTO",
    live_fingerprint=surface_fingerprint(tools),
)
print(decision.status, "-", decision.reason)
assert decision.status == "requires_approval"

# Unknown servers are refused; tools the audit never saw need a human.
assert policy.evaluate(server_id="other", tool_name="list_issues").status == "blocked"
assert policy.evaluate(server_id="issues", tool_name="drop_database").status == "requires_approval"
```

A longer example is in [`examples/basic_audit.py`](examples/basic_audit.py).

## Concepts

### Classification

`classify_tool` splits a tool's name and description into lowercase word tokens and looks for known verbs:

- **destructive** (`delete`, `drop`, `exec`, `shell`, `transfer`, `refund`, ...): `DRAFT_ONLY`, or `BLOCKED` with `ClassificationPolicy(block_destructive=True)`;
- **state-changing** (`create`, `update`, `send`, `deploy`, ...): `DRAFT_ONLY`;
- **read-only** (`get`, `list`, `search`, ...), with no verb from the two lists above: `READ_ONLY`;
- **no recognised verb**, or non-ASCII characters in the name: `DRAFT_ONLY`.

Destructive verbs win over read-only ones, so `list_and_delete` is destructive. Hosts can add terms with `ClassificationPolicy().with_extra(...)`.

### Clearance levels

| Level | When | Effect on a call |
|---|---|---|
| `READ_ONLY` | Every tool classifies read-only **and** the overseer says `SAFE`, or a person sets it | Auto-approved in `AUTO` mode; otherwise needs approval |
| `DRAFT_ONLY` | The default: any mutating, destructive or unrecognised tool; an empty surface; overseer `REVIEW`, `UNAVAILABLE` or `SKIPPED` | Needs human approval |
| `BLOCKED` | Overseer `MALICIOUS`, strict-mode destructive tools, or a person sets it | Refused |

The recommended clearance is the stricter of the static result and the overseer floor. A static-only audit (no overseer, or the overseer turned off) is never more open than a failed overseer: both give at least `DRAFT_ONLY`.

### Allowlist

`AllowlistPolicy` holds one `AllowlistedServer` per server. The entry's `clearance` is authoritative: it starts as the audit's recommendation, and a person may raise or lower it. `allowed_tools` is an optional per-tool grant. When it is set, only those exact names may be called and every other tool is blocked. `revoke()` marks a server revoked. `to_dict()` and `from_dict()` round-trip the policy as plain JSON or YAML data.

### Enforcement

`AllowlistPolicy.evaluate()` checks, in order:

1. Policy disabled (the default): `blocked`.
2. Missing or unknown `server_id`, or a server whose status is not `active`: `blocked`.
3. Blank tool name, or a tool outside the per-tool grant: `blocked`.
4. `live_fingerprint` given and different from the audited one (or none on file): `blocked`.
5. Effective clearance = stricter of the server clearance and the tool's audited clearance. A tool missing from the audit counts as at least `DRAFT_ONLY`. If a name is listed twice, the stricter entry counts.
6. `BLOCKED`: `blocked`. `READ_ONLY` with `execution_mode="AUTO"`: `auto_approved`. Anything else: `requires_approval`.

Tool names are matched exactly: `GET_X` is not `get_x`. `enforce_from_report()` and `enforce_tool_call()` expose steps 3 to 6 to hosts that keep their own registry.

### Surface fingerprint and drift

`surface_fingerprint(tools)` is a SHA-256 over each tool's name, description and input-schema property names. The audit stores it in the report. To catch a server that changed its tools after the audit, fetch the live list and either:

- pass `live_fingerprint=surface_fingerprint(live_tools)` to `evaluate()`, which blocks calls until you re-audit, or
- call `detect_drift(report, live_tools)`, which lists added and removed names. A report without a fingerprint counts as drift.

## Optional: overseer hook

An overseer is any callable, sync or async, that takes the tool list and returns `(verdict, rationale)`. The verdict is `SAFE`, `REVIEW`, `MALICIOUS` or `UNAVAILABLE`. The library ships the prompt and the parser, not an LLM client:

```python
from mcp_auditor import build_overseer_prompt, parse_overseer_text

def call_llm(system: str, user: str) -> str:
    # Replace with your model client; return the model's text reply.
    return '{"verdict": "REVIEW", "rationale": "creates issues"}'

def overseer(tools):
    system, user = build_overseer_prompt(tools)
    return parse_overseer_text(call_llm(system, user))

report = audit_tool_surface_sync(tools, overseer=overseer)
assert report.overseer_verdict == "REVIEW"
assert report.recommended_clearance is ClearanceLevel.DRAFT_ONLY
```

Use `await audit_tool_surface(...)` inside an event loop. If the overseer raises, or returns anything other than two strings with a known verdict, the verdict is `UNAVAILABLE` and the floor is `DRAFT_ONLY`. `parse_overseer_text` reads `SAFE` only from a strict JSON reply. `extract_response_text` pulls the text out of a chat-completion style response.

## Optional: live fetch

To enumerate a running server's tools, install the `fetch` extra, which adds the official MCP Python SDK (version 1.8 or newer; tested with 1.8, 1.30 and 2.3):

```bash
pip install "mcp-auditor[fetch] @ git+https://github.com/Combynr/mcp_auditor"
# or, from a local clone:
pip install -e ".[fetch]"
```

```python
import asyncio
from mcp_auditor import McpServerTarget, audit_server, fetch_server_tools

stdio_target = McpServerTarget(
    transport="stdio",
    command=["python", "my_server.py"],
    timeout_seconds=30,
)
http_target = McpServerTarget(
    transport="http",
    server_url="https://mcp.example.com/mcp",
    headers={"Authorization": "Bearer <token>"},
    timeout_seconds=30,
)

async def main() -> None:
    report = await audit_server(stdio_target, use_overseer=False)
    print(report.summary)
    live_tools = await fetch_server_tools(http_target)
    print([tool.name for tool in live_tools])

if __name__ == "__main__":
    asyncio.run(main())
```

Enumeration follows `tools/list` pagination. `timeout_seconds` bounds the whole enumeration, and an error is raised instead of returning a partial list.

## Limitations

- **The classifier is a heuristic over names and descriptions.** A destructive tool that is renamed and described blandly (for example `delete_all` exposed as `get_report`, "Returns the report") is classified `READ_ONLY`. Unrecognised verbs floor to `DRAFT_ONLY`, but a benign-looking name can still look read-only. The compensating controls are the overseer review and human clearance decisions. Neither is a proof of safety.
- **camelCase names are one token.** `getIssue` matches no verb and gets `DRAFT_ONLY`. This is stricter than intended, not more open.
- **The overseer reads text the server controls.** Tool descriptions can carry prompt injection. A `SAFE` verdict can never lower the clearance below the static result, but on a surface that already looks read-only it is what allows auto-approval. The library puts no time limit on the overseer call, so bound it in your callable.
- **This is not a sandbox.** It decides whether a call may proceed. It does not inspect arguments or results, and it cannot see what a server does behind a tool name. A server can behave differently from what it advertises. Your host must call `evaluate()` on every execution path.
- **The fingerprint covers names, descriptions and input-schema property names only.** It does not cover property types or descriptions, output schemas or annotations.
- **No persistence, approval inbox or audit log.** These belong to the host.
- `McpServerTarget.to_dict()` includes `headers` and `env` verbatim. Do not log or persist it if they hold credentials.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The tests need no network access. The live-fetch tests start real local MCP servers and are skipped when the SDK is not installed (`pip install -e ".[dev,fetch]"` to run them). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Versioning

The project follows [Semantic Versioning](https://semver.org/). The public API is the set of names exported in `mcp_auditor.__all__`. The current version is in `mcp_auditor.__version__`, and changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Security

Please report vulnerabilities privately to **security@combynr.com**. Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
