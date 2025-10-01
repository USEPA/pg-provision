import pytest


@pytest.mark.unit
def test_self_heal_flag_default_true(bash):
    script = r"""
      : "${SELF_HEAL:=unset}"
      # parse_args sets defaults (SELF_HEAL default should be true)
      parse_args --dry-run
      printf 'SELF_HEAL=%s\n' "${SELF_HEAL}"
    """
    r = bash(script)
    assert r.rc == 0, r.stderr
    assert "SELF_HEAL=true" in r.stdout


@pytest.mark.unit
def test_self_heal_flag_disable(bash):
    script = r"""
      parse_args --no-self-heal --dry-run
      printf 'SELF_HEAL=%s\n' "${SELF_HEAL}"
    """
    r = bash(script)
    assert r.rc == 0, r.stderr
    assert "SELF_HEAL=false" in r.stdout
