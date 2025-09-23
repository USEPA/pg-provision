"""
Managed block tests for hardened configuration edits (migrated).

Covers:
- HBA managed header is written at the top, single block, vendor lines preserved
- pg_ident managed block contains explicit entries, idempotent, preserves mode
- Generic managed-block rewriter (replace_managed_block_top) preserves mode and inserts at top
"""

import os
import re

import pytest


def _first_meaningful_line(text: str) -> str:
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        return ln
    return ""


@pytest.mark.unit
def test_hba_managed_header_top_singleton_preserves_vendor(tmp_path, bash):
    hba = tmp_path / "pg_hba.conf"
    # Seed with a vendor/default line below
    hba.write_text(
        "# vendor default\nhost all all 127.0.0.1/32 scram-sha-256\n", encoding="utf-8"
    )

    env = {"HBA": str(hba), "LOCAL_PEER_MAP": "localmap"}
    r1 = bash('apply_hba_policy "$HBA"', env=env)
    assert r1.rc == 0, r1.stderr
    r2 = bash('apply_hba_policy "$HBA"', env=env)
    assert r2.rc == 0, r2.stderr

    text = hba.read_text(encoding="utf-8")
    # Header begin marker should be at the very top (allow leading blanks)
    assert text.lstrip().startswith("# pgprovision:hba begin (managed)")
    # Exactly one header block (begin and end) present
    assert (
        len(re.findall(r"^\s*# pgprovision:hba begin \(managed\)\s*$", text, re.M)) == 1
    )
    assert len(re.findall(r"^\s*# pgprovision:hba end\s*$", text, re.M)) == 1
    # Vendor line still present after the block
    assert re.search(
        r"^\s*host\s+all\s+all\s+127\.0\.0\.1/32\s+scram-sha-256\s*$", text, re.M
    )


@pytest.mark.unit
def test_pg_ident_managed_block_entries_and_mode_preserved(tmp_path, bash):
    ident = tmp_path / "pg_ident.conf"
    ident.touch()
    os.chmod(ident, 0o640)

    script = r"""
      IDENT="${IDENT:?}"
      LOCAL_PEER_MAP=localmap
      # Define array with two explicit mappings
      LOCAL_MAP_ENTRIES=("alice:alice_db" "svc:svc")
      write_pg_ident_map "$IDENT"
      write_pg_ident_map "$IDENT"  # idempotent
    """
    r = bash(script, env={"IDENT": str(ident)})
    assert r.rc == 0, r.stderr

    text = ident.read_text(encoding="utf-8")
    assert (
        len(re.findall(r"^\s*# pgprovision:pg_ident begin \(managed\)\s*$", text, re.M))
        == 1
    )
    assert len(re.findall(r"^\s*# pgprovision:pg_ident end\s*$", text, re.M)) == 1
    assert re.search(r"^\s*localmap\s+alice\s+alice_db\s*$", text, re.M)
    assert re.search(r"^\s*localmap\s+svc\s+svc\s*$", text, re.M)
    # Mode preserved
    assert (os.stat(ident).st_mode & 0o777) == 0o640


@pytest.mark.unit
def test_replace_managed_block_preserves_mode_and_top_insertion(tmp_path, bash):
    f = tmp_path / "some.conf"
    f.write_text("keep1\nkeep2\n", encoding="utf-8")
    os.chmod(f, 0o644)

    script = r"""
      F="${F:?}"
      begin="# test:begin"
      end="# test:end"
      payload=$'# test:begin\nlineA\n# test:end'
      replace_managed_block_top "$F" "$begin" "$end" "$payload"
      # Second run with changed payload; should still be singleton
      payload=$'# test:begin\nlineB\n# test:end'
      replace_managed_block_top "$F" "$begin" "$end" "$payload"
      cat "$F"
    """
    r = bash(script, env={"F": str(f)})
    assert r.rc == 0, r.stderr

    text = f.read_text(encoding="utf-8")
    # Block is at top (allow leading blanks)
    assert text.lstrip().startswith("# test:begin")
    # Singleton
    assert len(re.findall(r"^\s*# test:begin\s*$", text, re.M)) == 1
    assert len(re.findall(r"^\s*# test:end\s*$", text, re.M)) == 1
    # Original lines preserved after block
    assert re.search(r"^keep1$", text, re.M)
    assert re.search(r"^keep2$", text, re.M)
    # Mode preserved
    assert (os.stat(f).st_mode & 0o777) == 0o644
