"""
Unit tests for write_stamp's psql fallback behavior when no data_dir argument is provided.
"""

import json

import pytest


@pytest.mark.unit
def test_write_stamp_psql_fallback_creates_json(tmp_path, bash):
    dd = tmp_path / "pgdata"
    dd.mkdir()
    env = {"DD": str(dd)}
    script = r"""
      # Stub psql to print the desired data_directory
      psql() { echo "${DD:?}"; }
      write_stamp ""
    """
    r = bash(script, env=env)
    assert r.rc == 0, r.stderr

    stamp = dd / ".pgprovision_provisioned.json"
    assert stamp.exists(), "stamp json not created via fallback"
    meta = json.loads(stamp.read_text(encoding="utf-8"))
    assert set(
        ["port", "listen_addresses", "repo", "allow_network", "enable_tls", "profile"]
    ).issubset(meta.keys())
