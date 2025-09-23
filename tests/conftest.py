"""
Pytest fixtures and helpers for the pgprovision test suite (migrated).

- Robustly locates and sources the new provision script.
- Defines SUDO=() to avoid unbound array errors under `set -u`.
- Provides a `bash` helper for running shell snippets with functions loaded.
- Registers markers and auto-skips for environment-dependent tests.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, NamedTuple, Optional

import pytest


# Ensure importing pgprovision from src without installing
_SRC = (Path(__file__).resolve().parents[1] / "src").as_posix()
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def pytest_configure(config):
    for m in [
        "unit: fast tests; no sudo/system changes",
        "integration: requires systemd/psql; may query live service",
        "requires_psql: skips if psql not available",
        "requires_systemd: skips if systemctl not available",
    ]:
        config.addinivalue_line("markers", m)


def pytest_runtest_setup(item):
    # Auto-skip for environment-dependent tests
    if item.get_closest_marker("requires_psql") and not shutil.which("psql"):
        pytest.skip("requires psql")
    if item.get_closest_marker("requires_systemd") and not shutil.which("systemctl"):
        pytest.skip("requires systemd")


class BashResult(NamedTuple):
    stdout: str
    stderr: str
    rc: int


def _candidate_provision_paths(repo_root: Path):
    # Respect explicit override first
    env = os.getenv("PROVISION_SH")
    if env:
        p = Path(env)
        if p.exists():
            yield p
    # Typical locations in the new repo
    for rel in [
        "src/pgprovision/_sh/provision.sh",
        "src/pgprovision/provision.sh",
        "provision.sh",
        "scripts/provision.sh",
        "bin/provision.sh",
    ]:
        p = repo_root / rel
        if p.exists():
            yield p


@pytest.fixture(scope="session")
def repo_root() -> Path:
    root = os.getenv("REPO_ROOT")
    return (
        Path(root).resolve() if root else Path(__file__).resolve().parents[1]
    )  # tests/..


@pytest.fixture(scope="session")
def provision_sh(repo_root: Path) -> Path:
    for p in _candidate_provision_paths(repo_root):
        return p.resolve()
    raise FileNotFoundError(
        "Could not locate provision.sh. "
        "Set PROVISION_SH=/absolute/path/to/provision.sh or adjust conftest.py search paths."
    )


@pytest.fixture(scope="session")
def psql_available() -> bool:
    return shutil.which("psql") is not None


@pytest.fixture(scope="session")
def systemd_available() -> bool:
    return shutil.which("systemctl") is not None


@pytest.fixture
def bash(provision_sh: Path) -> Callable[[str, Optional[Dict[str, str]]], BashResult]:
    """
    Run `bash -lc` with provision.sh sourced, returning (stdout, stderr, rc).
    Defines SUDO=() after sourcing to prevent unbound array expansions.

    Safety:
    - Does not invoke package managers or systemd by itself.
    - Callers must keep snippets side-effect free (use tmp paths, stubs).
    """

    def _run(cmd: str, env: Optional[Dict[str, str]] = None) -> BashResult:
        full = (
            "set -Ee -o pipefail;"
            "set +u;"
            f". '{provision_sh}';"
            "SUDO=();"
            "PROFILE_OVERRIDES=();"
            'if [[ "${PGPROVISION_STUB_ELEVATION:-1}" != "0" ]]; then\n'
            "  sudo() {\n"
            "    local -a args=()\n"
            "    while (( $# )); do\n"
            '      case "$1" in\n'
            "        -n) shift 1 ;;\n"
            "        -u) shift 2 ;;\n"
            '        *) args+=("$1"); shift ;;\n'
            "      esac\n"
            "    done\n"
            '    "${args[@]}"\n'
            "  }\n"
            "  chown() { return 0; }\n"
            "fi;"
            "set -u;"
            f"{cmd}"
        )
        proc = subprocess.run(
            ["bash", "-lc", full],
            text=True,
            capture_output=True,
            env={**os.environ, **(env or {}), "LC_ALL": "C"},
            timeout=60,
        )
        return BashResult(proc.stdout, proc.stderr, proc.returncode)

    return _run
