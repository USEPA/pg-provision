import pytest


def _make_stub(tmpdir, name, body='#!/bin/sh\necho STUB:$0 "$@"'):
    p = tmpdir / name
    p.write_text(body + "\n", encoding="utf-8")
    p.chmod(0o755)
    return p


@pytest.mark.unit
def test_rhel_heal_noop_when_unit_missing(tmp_path, bash):
    # Stub systemctl: 'list-unit-files' succeeds (no versioned unit),
    # but 'cat' fails to simulate unit not installed yet.
    _make_stub(
        tmp_path,
        "systemctl",
        body=r"""#!/bin/sh
case "$1" in
  list-unit-files) exit 0 ;;
  cat) exit 1 ;;
  *) exit 0 ;;
esac
""",
    )

    script = f"""
      export PATH="{tmp_path}:$PATH"
      OS_FAMILY=rhel; PG_VERSION=16; load_os_module
      _rhel_self_heal_cluster
    """
    r = bash(script)
    assert r.rc == 0, r.stderr
    # No warning spam before packages/units exist
    assert "RHEL self-heal: detected broken cluster" not in r.stdout
