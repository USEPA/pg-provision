"""
Tests for PROFILE_OVERRIDES and PROFILE-driven idempotent drop-in rendering.

Focus:
- PROFILE_OVERRIDES applied twice → singleton keys, no duplicates
- Changing PROFILE_OVERRIDES between runs updates value without dupes
- Integration: load_profile_overrides reads built-in profile and writes keys once
"""

import re

import pytest


def _read_dropins_text(conf_dir):
    dropin_dir = conf_dir / "conf.d"
    files = list(dropin_dir.glob("*.conf"))
    assert files, "No drop-in written to conf.d"
    return "\n".join(f.read_text(encoding="utf-8") for f in files)


@pytest.mark.unit
def test_profile_overrides_idempotent_singleton(tmp_path, bash):
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    script = r"""
      CONF="${CONF:?}"; DATA="${DATA:?}"
      PROFILE_OVERRIDES=("work_mem=64MB" "shared_buffers=128MB")
      apply_dropin_config "$CONF" "$DATA"
      apply_dropin_config "$CONF" "$DATA"  # idempotent re-run
    """
    r = bash(script, env={"CONF": str(conf), "DATA": str(tmp_path)})
    assert r.rc == 0, r.stderr

    content = _read_dropins_text(tmp_path)
    assert len(re.findall(r"^\s*work_mem\s*=\s*64MB\s*$", content, re.M)) == 1
    assert len(re.findall(r"^\s*shared_buffers\s*=\s*128MB\s*$", content, re.M)) == 1


@pytest.mark.unit
def test_profile_overrides_update_without_duplication(tmp_path, bash):
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    script1 = r"""
      CONF="${CONF:?}"; DATA="${DATA:?}"
      PROFILE_OVERRIDES=("work_mem=64MB")
      apply_dropin_config "$CONF" "$DATA"
    """
    r1 = bash(script1, env={"CONF": str(conf), "DATA": str(tmp_path)})
    assert r1.rc == 0, r1.stderr

    script2 = r"""
      CONF="${CONF:?}"; DATA="${DATA:?}"
      PROFILE_OVERRIDES=("work_mem=32MB")
      apply_dropin_config "$CONF" "$DATA"
    """
    r2 = bash(script2, env={"CONF": str(conf), "DATA": str(tmp_path)})
    assert r2.rc == 0, r2.stderr

    content = _read_dropins_text(tmp_path)
    assert len(re.findall(r"^\s*work_mem\s*=\s*32MB\s*$", content, re.M)) == 1
    assert not re.search(r"^\s*work_mem\s*=\s*64MB\s*$", content, re.M)


@pytest.mark.unit
def test_load_profile_overrides_integration_and_dropin(tmp_path, bash):
    conf = tmp_path / "postgresql.conf"
    conf.touch()

    script = r"""
      CONF="${CONF:?}"; DATA="${DATA:?}"
      PROFILE=xl-32c-256g
      load_profile_overrides
      apply_dropin_config "$CONF" "$DATA"
      apply_dropin_config "$CONF" "$DATA"  # idempotent re-run
    """
    r = bash(script, env={"CONF": str(conf), "DATA": str(tmp_path)})
    assert r.rc == 0, r.stderr

    content = _read_dropins_text(tmp_path)
    # Check a couple of representative keys from the built-in profile
    assert len(re.findall(r"^\s*work_mem\s*=\s*32MB\s*$", content, re.M)) == 1
    assert len(re.findall(r"^\s*shared_buffers\s*=\s*64GB\s*$", content, re.M)) == 1
