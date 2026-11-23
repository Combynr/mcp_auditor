"""The README code blocks and the example script run as written."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _python_blocks(text: str) -> list[str]:
    return re.findall(r"```python\n(.*?)```", text, flags=re.DOTALL)


def test_readme_python_blocks_run_in_order():
    blocks = _python_blocks((ROOT / "README.md").read_text(encoding="utf-8"))
    assert len(blocks) >= 3
    namespace: dict = {"__name__": "readme"}
    for block in blocks:
        exec(compile(block, "README.md", "exec"), namespace)  # noqa: S102


def test_example_script_runs():
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "basic_audit.py")],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "docs/search_docs: auto_approved" in result.stdout


def test_versions_agree():
    from mcp_auditor import __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in pyproject
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {__version__} " in changelog
