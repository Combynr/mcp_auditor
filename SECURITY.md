# Security policy

mcp:auditor is a security control, so we treat any way to get a call
`auto_approved` that the documented rules would not allow (a fail-open path) as
a vulnerability. That includes bypasses of the allowlist, the per-tool grant,
the fingerprint check, or the overseer floor.

## Reporting a vulnerability

Email **security@combynr.com** with:

- a description of the issue and its impact;
- the version (`mcp_auditor.__version__`) or commit;
- steps or a minimal script that reproduces it.

Please do not open a public issue, pull request or discussion for a suspected
vulnerability until it is fixed.

What to expect:

- an acknowledgement within 3 business days;
- an initial assessment within 10 business days;
- a fix or mitigation plan agreed with you, normally within 90 days; we will
  ask before disclosing details publicly and will credit you in the changelog
  unless you prefer otherwise.

## Supported versions

Security fixes are made on the latest release only.

## Scope

In scope: the code in this repository.

Out of scope: the documented limitations in the README (the classifier being
a name and description heuristic, prompt injection against an overseer you
supply, and anything that happens inside an MCP server after a call has been
approved). Reports that show these limitations are worse than documented are
welcome.

## Design guarantees

- Every decision path that is not explicitly allowed ends in
  `requires_approval` or `blocked`.
- An overseer that is unavailable, skipped, raising, or returning malformed
  output floors to `DRAFT_ONLY`; it never opens access.
- The library stores nothing; the host owns persistence. Note that
  `McpServerTarget.to_dict()` includes `headers` and `env` verbatim.
- Tool names and descriptions from MCP servers are treated as untrusted input.
