import pytest


def _make_stub(tmpdir, name, body="#!/bin/sh\nexit 0"):
    p = tmpdir / name
    p.write_text(body + "\n", encoding="utf-8")
    p.chmod(0o755)
    return p


@pytest.mark.unit
def test_apply_dropin_idempotent_and_content(tmp_path, bash):
    # Stubs to avoid root requirements
    _make_stub(tmp_path, "chown")
    _make_stub(tmp_path, "restorecon")
    _make_stub(
        tmp_path,
        "install",
        body=r"""#!/bin/sh
# naive install -d stub: create last arg dir
last=""
for a in "$@"; do last="$a"; done
mkdir -p "$last"
exit 0
""",
    )

    conf = tmp_path / "postgresql.conf"
    conf.write_text("# base\n", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()

    script = f"""
      export PATH="{tmp_path}:$PATH"
      PORT=5433
      LISTEN_ADDRESSES="*"
      UNIX_SOCKET_GROUP=pgclients
      UNIX_SOCKET_PERMISSIONS=0770
      ENABLE_TLS=false
      SUDO=()  # ensure wrappers don't try sudo

      apply_dropin_config "{conf}" "{data}"
      apply_dropin_config "{conf}" "{data}"   # idempotent
    """
    r = bash(script)
    assert r.rc == 0, r.stderr

    # Validate include_dir appears exactly once
    conf_text = conf.read_text(encoding="utf-8")
    assert conf_text.count("include_dir = 'conf.d'") == 1

    dropin = conf.parent / "conf.d" / "99-pgprovision.conf"
    body = dropin.read_text(encoding="utf-8")
    assert "port = 5433" in body
    assert "listen_addresses = '*'" in body
    assert "shared_preload_libraries = 'pg_stat_statements'" in body
