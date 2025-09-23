"""
Configuration and file-behavior tests against the new pgprovision functions.

Covers:
- include_dir idempotency in postgresql.conf via apply_dropin_config
- TLS options added when ENABLE_TLS=true (whitespace-agnostic)
- Existing data-dir permissions preserved by write_stamp/ensure_dir
- write_key_value_dropin updates in-place without duplicates
"""

import json
import os
import re
import sys

import pytest


@pytest.mark.unit
def test_include_dir_idempotent(tmp_path, bash):
    """
    Ensures apply_dropin_config adds exactly one "include_dir = 'conf.d'" line,
    even when invoked twice on the same postgresql.conf (idempotent).
    Uses whitespace-agnostic matching.
    """
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    env = {"CONF": str(conf), "DATA": str(tmp_path)}
    r1 = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r1.rc == 0, r1.stderr
    r2 = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r2.rc == 0, r2.stderr

    text = conf.read_text(encoding="utf-8")
    pat = r"^\s*include_dir\s*=\s*'conf\.d'\s*$"
    assert len(re.findall(pat, text, re.M)) == 1


@pytest.mark.unit
def test_tls_dropin_writes_ssl_options(tmp_path, bash):
    """
    When ENABLE_TLS=true, apply_dropin_config must write expected TLS settings
    into conf.d drop-ins. Do not couple to a specific filename; aggregate content
    from all *.conf files.
      - ssl = on
      - ssl_min_protocol_version = TLSv1.2
      - ssl_prefer_server_ciphers = on
    """
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    env = {
        "CONF": str(conf),
        "DATA": str(tmp_path),
        "ENABLE_TLS": "true",
        "PORT": "5432",
        "LISTEN_ADDRESSES": "localhost",
    }
    r1 = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r1.rc == 0, r1.stderr

    # Idempotency: second call should not duplicate TLS lines
    r2 = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r2.rc == 0, r2.stderr

    dropin_dir = tmp_path / "conf.d"
    files = list(dropin_dir.glob("*.conf"))
    assert files, "No drop-in written to conf.d"
    content = "\n".join(f.read_text(encoding="utf-8") for f in files)

    assert len(re.findall(r"^\s*ssl\s*=\s*on\s*$", content, re.M)) == 1
    assert (
        len(
            re.findall(
                r"^\s*ssl_min_protocol_version\s*=\s*TLSv1\.2\s*$", content, re.M
            )
        )
        == 1
    )
    assert (
        len(re.findall(r"^\s*ssl_prefer_server_ciphers\s*=\s*on\s*$", content, re.M))
        == 1
    )


@pytest.mark.unit
def test_tls_disabled_has_no_ssl_options(tmp_path, bash):
    """
    When ENABLE_TLS is not set/false, TLS-related keys must not be present
    in any conf.d drop-in.
    """
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    env = {"CONF": str(conf), "DATA": str(tmp_path)}
    r = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r.rc == 0, r.stderr

    dropin_dir = tmp_path / "conf.d"
    files = list(dropin_dir.glob("*.conf"))
    assert files, "No drop-in written to conf.d"
    content = "\n".join(f.read_text(encoding="utf-8") for f in files)

    assert not re.search(r"^\s*ssl\s*=\s*on\s*$", content, re.M)
    assert not re.search(
        r"^\s*ssl_min_protocol_version\s*=\s*TLSv1\.2\s*$", content, re.M
    )
    assert not re.search(r"^\s*ssl_prefer_server_ciphers\s*=\s*on\s*$", content, re.M)


@pytest.mark.unit
@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="POSIX-only permissions semantics"
)
def test_existing_data_dir_perms_preserved_and_stamp_json(tmp_path, bash):
    """
    write_stamp must not alter an already-existing directory’s permissions (e.g., 0700).
    Also verifies stamp JSON structure and a couple of default values.
    """
    os.chmod(tmp_path, 0o700)
    env = {"DATA": str(tmp_path)}
    r = bash('write_stamp "$DATA"', env=env)
    assert r.rc == 0, r.stderr

    st = os.stat(tmp_path)
    mode = st.st_mode & 0o777
    assert mode == 0o700

    stamp = tmp_path / ".pgprovision_provisioned.json"
    assert stamp.exists(), "stamp file was not created"
    meta = json.loads(stamp.read_text(encoding="utf-8"))
    # loose structure checks (avoid coupling to env in CI)
    assert set(
        ["port", "listen_addresses", "repo", "allow_network", "enable_tls", "profile"]
    ).issubset(meta.keys())
    assert meta["port"] == 5432
    assert meta["listen_addresses"] == "localhost"


@pytest.mark.unit
def test_write_key_value_dropin_updates_in_place(tmp_path, bash):
    """
    write_key_value_dropin must update an existing key in-place (sed replace)
    rather than appending duplicates; final line should reflect the last value.
    Uses whitespace-agnostic matching.
    """
    dropin = tmp_path / "99.conf"
    env = {"F": str(dropin)}

    r1 = bash('write_key_value_dropin "$F" maintenance_work_mem 64MB', env=env)
    assert r1.rc == 0, r1.stderr
    r2 = bash('write_key_value_dropin "$F" maintenance_work_mem 32MB', env=env)
    assert r2.rc == 0, r2.stderr

    text = dropin.read_text(encoding="utf-8")
    pat = r"^\s*maintenance_work_mem\s*=\s*32MB\s*$"
    assert len(re.findall(pat, text, re.M)) == 1
    # Ensure no duplicate lines for the key
    assert len(re.findall(r"^\s*maintenance_work_mem\s*=", text, re.M)) == 1


@pytest.mark.unit
def test_write_key_value_dropin_quotes_and_commas(tmp_path, bash):
    """
    Exercise quoting and comma-separated values:
    - log_line_prefix should be written as a single-quoted string with spaces and brackets.
    - shared_preload_libraries should be written as a single-quoted comma list.
    - Both keys should appear exactly once.
    """
    dropin = tmp_path / "extra.conf"
    env = {
        "F": str(dropin),
        "LOGP": r"%m [%p] %q%u@%d ",
        "SPL": "pg_stat_statements,auto_explain",
    }

    r1 = bash(
        """
      write_key_value_dropin "$F" log_line_prefix "'$LOGP'"
      # PostgreSQL expects string values in single quotes; use single-quoted
      # comma list for shared_preload_libraries.
      write_key_value_dropin "$F" shared_preload_libraries "'$SPL'"
        """,
        env=env,
    )
    assert r1.rc == 0, r1.stderr

    text = dropin.read_text(encoding="utf-8")
    assert re.search(r"^\s*log_line_prefix\s*=\s*'%m \[%p\] %q%u@%d '\s*$", text, re.M)
    assert re.search(
        r"^\s*shared_preload_libraries\s*=\s*'pg_stat_statements,auto_explain'\s*$",
        text,
        re.M,
    )
    assert len(re.findall(r"^\s*log_line_prefix\s*=", text, re.M)) == 1
    assert len(re.findall(r"^\s*shared_preload_libraries\s*=", text, re.M)) == 1


@pytest.mark.unit
def test_apply_dropin_core_keys_idempotent(tmp_path, bash):
    """
    apply_dropin_config must set core keys exactly once and be idempotent.
    We verify a subset that are critical defaults irrespective of TLS:
      - password_encryption = scram-sha-256
      - shared_preload_libraries includes 'pg_stat_statements'
      - log_line_prefix has the expected format
    """
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    env = {"CONF": str(conf), "DATA": str(tmp_path)}
    r1 = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r1.rc == 0, r1.stderr
    r2 = bash('apply_dropin_config "$CONF" "$DATA"', env=env)
    assert r2.rc == 0, r2.stderr

    dropin_dir = tmp_path / "conf.d"
    files = list(dropin_dir.glob("*.conf"))
    assert files, "No drop-in written to conf.d"
    content = "\n".join(f.read_text(encoding="utf-8") for f in files)

    assert (
        len(
            re.findall(
                r"^\s*password_encryption\s*=\s*scram-sha-256\s*$", content, re.M
            )
        )
        == 1
    )
    assert (
        len(
            re.findall(
                r"^\s*shared_preload_libraries\s*=\s*'pg_stat_statements'\s*$",
                content,
                re.M,
            )
        )
        == 1
    )
    assert (
        len(
            re.findall(
                r"^\s*log_line_prefix\s*=\s*'%m \[%p\] user=%u db=%d app=%a client=%h '\s*$",
                content,
                re.M,
            )
        )
        == 1
    )


@pytest.mark.unit
def test_parse_args_flags_and_unknown(tmp_path, bash):
    """
    parse_args should map common flags to variables and reject unknown flags.
    """
    r = bash(
        """
      parse_args --enable-tls --allow-network --socket-only \
                 --port 5555 --listen-addresses '*' \
                 --local-peer-map map1 --local-map-entry alice:db1
      echo "TLS=${ENABLE_TLS} AN=${ALLOW_NETWORK} SO=${SOCKET_ONLY} PORT=${PORT} LISTEN=${LISTEN_ADDRESSES} LPM=${LOCAL_PEER_MAP} LME=${LOCAL_MAP_ENTRIES[*]}"
        """
    )
    assert r.rc == 0, r.stderr
    out = r.stdout.strip()
    assert "TLS=true" in out
    assert "AN=true" in out
    assert "SO=true" in out
    assert "PORT=5555" in out
    assert "LISTEN=*" in out
    assert "LPM=map1" in out
    assert "LME=alice:db1" in out

    r2 = bash("parse_args --unknown-flag")
    assert r2.rc != 0
