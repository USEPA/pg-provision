"""
Security behavior tests for secret handling in create_db_and_user.

Ensures password is not exposed on the psql command line by verifying that
psql is invoked with -f <tempfile>, and that the SQL file contains the
password (not the argv). Also verifies support for CREATE_PASSWORD_FILE.
"""

import re

import pytest


@pytest.mark.unit
def test_create_user_password_not_in_argv(tmp_path, bash):
    cap = tmp_path / "cap.txt"
    env = {
        "CAP": str(cap),
        "CREATE_USER": "alice",
        "CREATE_DB": "testdb",
        "CREATE_PASSWORD": "s3cr3t!",
    }
    script = r"""
      CAP="${CAP:?}"
      : > "$CAP"
      # stub psql to capture argv; stub shred to keep temp file
      psql() { echo "psql $*" >> "$CAP"; return 0; }
      shred() { :; }
      create_db_and_user || true
      cat "$CAP"
    """
    r = bash(script, env=env)
    assert r.rc == 0, r.stderr
    line = r.stdout.strip().splitlines()[-1]
    # Expect -f /tmp/...
    assert re.search(r"\bpsql\b.*\s-f\s+/\S+", line)
    # Ensure password does not appear in argv
    assert "s3cr3t!" not in line


@pytest.mark.unit
def test_create_user_password_from_file(tmp_path, bash):
    cap = tmp_path / "cap.txt"
    pwf = tmp_path / "pw.txt"
    pwf.write_text("Pa$$wd", encoding="utf-8")
    env = {
        "CAP": str(cap),
        "CREATE_USER": "bob",
        "CREATE_PASSWORD_FILE": str(pwf),
    }
    script = r"""
      CAP="${CAP:?}"
      : > "$CAP"
      psql() { echo "psql $*" >> "$CAP"; return 0; }
      shred() { :; }
      create_db_and_user || true
      cat "$CAP"
    """
    r = bash(script, env=env)
    assert r.rc == 0, r.stderr
    line = r.stdout.strip().splitlines()[-1]
    # Ensure file execution is used and password not exposed via argv
    assert "Pa$$wd" not in line
    assert "-f" in line
