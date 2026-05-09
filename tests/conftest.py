from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def build_synthetic_examples() -> None:
    """Build generated ELF fixtures from checked-in assembly sources.

    The repository intentionally does not track examples/synthetic/bin/* so it
    stays small for GitHub.  Tests can still be run from a clean clone.
    """
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "build_synthetic.sh"
    subprocess.run([str(script)], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
