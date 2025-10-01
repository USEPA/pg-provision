import pathlib
import pytest


def _make_stub(
    tmpdir: pathlib.Path, name: str, body: str = '#!/bin/sh\necho STUB:$0 "$@"'
):
    p = tmpdir / name
    p.write_text(body + "\n", encoding="utf-8")
    p.chmod(0o755)
    return p


@pytest.mark.unit
def test_os_enable_and_start_fallback_without_systemd(tmp_path, bash):
    # PATH contains only our stubs; no systemctl present.
    _make_stub(tmp_path, "pg_ctlcluster")
    script = rf"""
      export PATH="{tmp_path}"
      OS_FAMILY=ubuntu; PG_VERSION=16; load_os_module
      os_enable_and_start "postgresql@16-main"
    """
    r = bash(script)
    assert r.rc == 0, r.stderr
    # Ensure fallback path invoked pg_ctlcluster
    assert "+ pg_ctlcluster" in r.stdout


@pytest.mark.unit
def test_os_restart_fallback_without_systemd(tmp_path, bash):
    _make_stub(tmp_path, "pg_ctlcluster")
    script = rf"""
      export PATH="{tmp_path}"
      OS_FAMILY=ubuntu; PG_VERSION=16; load_os_module
      os_restart "postgresql@16-main"
    """
    r = bash(script)
    assert r.rc == 0, r.stderr
    assert "+ pg_ctlcluster" in r.stdout
