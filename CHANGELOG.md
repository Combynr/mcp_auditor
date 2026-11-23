# Changelog

All notable changes to this project are listed here. The project follows
[Semantic Versioning](https://semver.org/).

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
