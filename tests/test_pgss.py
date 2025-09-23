"""
pg_stat_statements initialization behavior tests.

Verifies:
- Positive: when INIT_PG_STAT_STATEMENTS=true, the function
  conditionally_init_pg_stat_statements attempts to run a sudo+psql command
  and includes the CREATE EXTENSION SQL (tolerant to argument ordering).
- Negative: when the flag is absent/false, no invocation occurs.
"""

import pytest


@pytest.mark.unit
def test_pgss_flag_triggers_create_extension(tmp_path, bash):
    """
    Stubs sudo and psql to capture calls; asserts "sudo -u postgres", "psql",
    and the exact CREATE EXTENSION SQL appear in captured output.
    """
    cap = tmp_path / "cap.txt"
    env = {"INIT_PG_STAT_STATEMENTS": "true", "CAP": str(cap)}
    script = r"""
      CAP="${CAP:?}"
      : > "$CAP"
      sudo() { echo "sudo $*" >> "$CAP"; return 0; }
      psql() { echo "psql $*" >> "$CAP"; return 0; }
      conditionally_init_pg_stat_statements || true
      cat "$CAP"
    """
    r = bash(script, env=env)
    assert r.rc == 0, r.stderr

    out = r.stdout
    assert "sudo -u postgres" in out
    assert "psql" in out
    assert "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" in out


@pytest.mark.unit
def test_pgss_flag_absent_does_not_invoke(tmp_path, bash):
    """
    With INIT_PG_STAT_STATEMENTS unset/false, there must be no sudo/psql calls.
    """
    cap = tmp_path / "cap.txt"
    env = {"CAP": str(cap)}
    script = r"""
      CAP="${CAP:?}"
      : > "$CAP"
      sudo() { echo "sudo $*" >> "$CAP"; return 0; }
      psql() { echo "psql $*" >> "$CAP"; return 0; }
      conditionally_init_pg_stat_statements || true
      cat "$CAP"
    """
    r = bash(script, env=env)
    assert r.rc == 0, r.stderr
    assert r.stdout.strip() == ""
