# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/).

## 1.1.0 — 2026-11-25

Additive: every 1.0 call keeps its result unless the host passes one of the new
inputs and the call breaks a rule it declares.

### Added

- `CallContext`: the caller's capabilities (from the host's access control), tenant
  and the agent's tool list. A call must pass all of them as well as the clearance.
  `READ_ONLY` calls need `mcp:read`, other calls `mcp:write`
  (`required_capability`).
- Argument rules: `ArgumentPolicy`, `ToolArgumentSchema`, `ArgumentRule` and
  `validate_arguments`. Strict types (a numeric string is not an integer and a
  bool is not a number), floors and caps, length, byte and item limits, paths that
  must resolve inside a workspace root, and recipient and domain allowlists for
  email and URL arguments. A violation is `blocked` with a reason naming the
  argument. A malformed rule refuses the call.
- High-risk families (`detect_families`, `HIGH_RISK_FAMILIES`): file write or
  delete, shell, email, outbound HTTP, office write-back. With a policy in force,
  such a call under a name the policy does not declare is held for approval, and
  a renamed tool whose arguments fit a declared schema of its family is checked
  against that schema.
- `enforce_from_report` and `AllowlistPolicy.evaluate` take `arguments`,
  `context` and `argument_policy`. `AllowlistedServer` stores `tenant_id` and
  `argument_policy`; both are serialised only when set, so a 1.0 policy
  round-trips unchanged. A report dict may carry an `argument_policy`.
- A server entry that names a tenant refuses a caller that names a different
  tenant or none.
- A built-in default pack (`DEFAULT_PACK`, `check_defaults`, `describe_defaults`)
  for high-risk calls that have no schema under their own name, so an empty
  `ArgumentPolicy()` protects with zero setup: path traversal, NUL, oversize
  writes, header injection in recipients, non-http(s) URLs and URLs with
  credentials are blocked; writes, shell, email and office write-back are held;
  HTTP to a public host keeps its clearance and to a private host is held.
  `ArgumentPolicy(defaults=False)` holds instead. A declared schema replaces the
  defaults for its tool.

## 1.0.2 — 2026-11-23

First public release.

### Security fixes (fail-open paths closed)

- `enforce_tool_call`: a clearance passed as a plain string (for example
  `"BLOCKED"`) fell through to `auto_approved`. Clearances are now coerced, and
  only an effective `READ_ONLY` can be auto-approved.
- `coerce_clearance` turned `ClearanceLevel` members into `DRAFT_ONLY`, which
  downgraded `BLOCKED` entries in reports built with enum values.
- `AllowlistPolicy.evaluate`: a server audited with zero tools fell back to
  the server clearance, so any tool name could be auto-approved. Tools missing
  from an audit on file now always need approval.
- `AllowlistPolicy.from_dict`: the string `"false"` for `enabled` switched the
  master gate on. Only an explicit yes enables it.
- `parse_overseer_text`: free text containing "SAFE", including "UNSAFE" and
  "not safe", parsed as `SAFE`. Only strict JSON can yield `SAFE` now.
- Classifier: upper-case extra terms never matched. Text is now NFKC-folded,
  and a tool name containing non-ASCII characters cannot be classified
  `READ_ONLY`.
- `detect_drift`: a report without a fingerprint passed when the names matched.
  It now reports drift.
- A name advertised twice now takes the stricter clearance. Blank tool names
  are blocked. A malformed `allowed_tools` value is read as an empty grant.

### Fixes

- Live HTTP enumeration failed on every supported MCP SDK: 2.x has no
  `streamablehttp_client`, and older 1.x releases crashed on the integer
  timeout. Both SDK lines now work, and the minimum is `mcp>=1.8`.
- `audit_tool_surface_sync` ignored an injected `overseer` unless
  `use_overseer=True` was also passed. It now uses the overseer when one is
  given.
- An overseer returning anything other than two strings with a known verdict
  is now recorded as `UNAVAILABLE` (floor `DRAFT_ONLY`).
- `extract_response_text` no longer raises on a missing message.

### Added

- `live_fingerprint` argument on `AllowlistPolicy.evaluate` and
  `enforce_from_report`. Calls are blocked when the live surface no longer
  matches the audit.
- Live enumeration follows `tools/list` pagination (bounded), applies
  `timeout_seconds` to both transports, and raises a clear error when the SDK
  is missing.
- Test suite expanded, including real stdio and HTTP MCP servers when the
  SDK is installed. README rewritten, plus CONTRIBUTING.md and a security
  disclosure process.

## 1.0.1 — 2026-10-10

- `fetch_server_tools` passes an HTTP target's `headers` (an API key, a bearer
  token) to the streamable-HTTP client. Before this, an authenticated MCP server
  could not be enumerated.

## 1.0.0 — 2026-07-24

- Initial release: classify, clearance, allowlist, enforce and fingerprint
  APIs; fail-closed overseer handling.
