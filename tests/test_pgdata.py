import shutil
import pytest


@pytest.mark.unit
def test_is_valid_pgdata_accepts_symlinked_wal(tmp_path, bash):
    # Arrange: build a minimal, valid PGDATA with symlinked pg_wal
    pg = tmp_path / "pgdata"
    (pg / "global").mkdir(parents=True)
    (pg / "base").mkdir()
    (pg / "global" / "pg_control").write_bytes(b"X")
    (pg / "PG_VERSION").write_text("16\n", encoding="utf-8")
    wal = tmp_path / "wal"
    wal.mkdir()
    (pg / "pg_wal").symlink_to(wal)

    script = f"""
      OS_FAMILY=ubuntu; PG_VERSION=16; load_os_module
      _is_valid_pgdata "{pg}"
      echo RC=$?
    """
    r = bash(script)
    assert r.rc == 0, r.stderr
    assert "RC=0" in r.stdout  # success


@pytest.mark.unit
@pytest.mark.parametrize("osfam", ["rhel", "ubuntu"])
@pytest.mark.parametrize("missing", ["PG_VERSION", "global/pg_control", "base"])
def test_is_valid_pgdata_fails_when_core_piece_missing(tmp_path, bash, osfam, missing):
    pg = tmp_path / "pgdata"
    (pg / "global").mkdir(parents=True)
    (pg / "base").mkdir()
    (pg / "PG_VERSION").write_text("16\n", encoding="utf-8")
    (pg / "global" / "pg_control").write_bytes(b"X")
    (pg / "pg_wal").mkdir()
    # Remove the one we want missing
    if missing == "PG_VERSION":
        (pg / "PG_VERSION").unlink()
    elif missing == "global/pg_control":
        (pg / "global" / "pg_control").unlink()
    elif missing == "base":
        shutil.rmtree(pg / "base")

    script = f"""
      OS_FAMILY={osfam}; PG_VERSION=16; load_os_module
      if _is_valid_pgdata "{pg}"; then echo RC=0; else echo RC=$?; fi
    """

    r = bash(script)
    assert r.rc == 0, r.stderr
    assert "RC=1" in r.stdout  # failure
