# Contributing

Thanks for helping. Issues and pull requests are welcome. For security
problems, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

```bash
git clone https://github.com/Combynr/mcp_auditor
cd mcp_auditor
pip install -e ".[dev]"          # ".[dev,fetch]" to also run the live-fetch tests
python -m pytest -q
```

## Guidelines

- Keep the library free of runtime dependencies. The MCP SDK stays an optional
  extra.
- Every behaviour change needs a test. A bug fix needs a test that fails without
  the fix.
- Fail closed. A change must not let a call reach `auto_approved` in a
  situation where it was previously `requires_approval` or `blocked`, unless the
  pull request explains why that is intended.
- Do not weaken an existing test to make a change pass.
- Update `CHANGELOG.md` and, where relevant, `README.md`.

## Sign-off (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. By signing off a commit you certify that you wrote it or
otherwise have the right to submit it under the project's MIT license. Add the
sign-off with `git commit -s`, which appends:

```
Signed-off-by: Your Name <you@example.com>
```

Pull requests with commits that are not signed off cannot be merged.
