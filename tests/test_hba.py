"""
HBA rules tests focusing on idempotency and conditional CIDR entries (migrated).

Covers:
- Default localhost/loopback entries added exactly once (idempotent)
  * local all postgres peer
  * local all all peer map=<LOCAL_PEER_MAP>
  * host 127.0.0.1/32 scram-sha-256
  * host ::1/128 scram-sha-256
- IPv4 CIDR added as 'host' when ENABLE_TLS=false
- IPv4 CIDR added as 'hostssl' when ENABLE_TLS=true
Using whitespace-agnostic token matching.
"""

import re

import pytest


def _pattern_for(*tokens: str) -> str:
    return r"^\s*" + r"\s+".join(map(re.escape, tokens)) + r"\s*$"


def has_hba_line(text: str, *tokens: str) -> bool:
    return re.search(_pattern_for(*tokens), text, re.M) is not None


def count_hba_lines(text: str, *tokens: str) -> int:
    return len(re.findall(_pattern_for(*tokens), text, re.M))


@pytest.mark.unit
def test_hba_idempotent_default_rules(tmp_path, bash):
    """
    apply_hba_policy must ensure exactly one of each default entry:
      - local all postgres peer
      - local all all peer map=LOCAL_PEER_MAP
      - IPv4 loopback scram
      - IPv6 loopback scram
    Subsequent invocations must not duplicate these lines.
    """
    hba = tmp_path / "pg_hba.conf"
    hba.touch()

    env = {"HBA": str(hba), "LOCAL_PEER_MAP": "localmap"}
    r1 = bash('apply_hba_policy "$HBA"', env=env)
    assert r1.rc == 0, r1.stderr
    r2 = bash('apply_hba_policy "$HBA"', env=env)
    assert r2.rc == 0, r2.stderr

    text = hba.read_text(encoding="utf-8")
    assert count_hba_lines(text, "local", "all", "postgres", "peer") == 1
    assert count_hba_lines(text, "local", "all", "all", "peer", "map=localmap") == 1
    assert (
        count_hba_lines(text, "host", "all", "all", "127.0.0.1/32", "scram-sha-256")
        == 1
    )
    assert count_hba_lines(text, "host", "all", "all", "::1/128", "scram-sha-256") == 1


@pytest.mark.unit
def test_hba_adds_ipv4_cidr_without_tls(tmp_path, bash):
    """
    When ALLOWED_CIDR is set and ENABLE_TLS is false/absent, apply_hba_policy
    must add a 'host' (not hostssl) CIDR rule for the given network. The rule
    should be idempotent across repeated invocations.
    """
    hba = tmp_path / "pg_hba.conf"
    hba.touch()

    env = {"HBA": str(hba), "ALLOWED_CIDR": "10.0.0.0/8"}
    r = bash('apply_hba_policy "$HBA"', env=env)
    assert r.rc == 0, r.stderr

    text = hba.read_text(encoding="utf-8")
    assert has_hba_line(text, "host", "all", "all", "10.0.0.0/8", "scram-sha-256")
    assert not has_hba_line(text, "hostssl", "all", "all", "10.0.0.0/8")

    r2 = bash('apply_hba_policy "$HBA"', env=env)
    assert r2.rc == 0, r2.stderr
    text2 = hba.read_text(encoding="utf-8")
    assert (
        count_hba_lines(text2, "host", "all", "all", "10.0.0.0/8", "scram-sha-256") == 1
    )


@pytest.mark.unit
def test_hba_adds_ipv4_cidr_with_tls_hostssl(tmp_path, bash):
    """
    When ALLOWED_CIDR is set and ENABLE_TLS=true, apply_hba_policy must add
    a 'hostssl' CIDR rule for the given network.
    """
    hba = tmp_path / "pg_hba.conf"
    hba.touch()

    env = {"HBA": str(hba), "ALLOWED_CIDR": "10.0.0.0/8", "ENABLE_TLS": "true"}
    r1 = bash('apply_hba_policy "$HBA"', env=env)
    assert r1.rc == 0, r1.stderr

    text1 = hba.read_text(encoding="utf-8")
    assert has_hba_line(text1, "hostssl", "all", "all", "10.0.0.0/8", "scram-sha-256")

    # Idempotent: second call should not duplicate
    r2 = bash('apply_hba_policy "$HBA"', env=env)
    assert r2.rc == 0, r2.stderr
    text2 = hba.read_text(encoding="utf-8")
    assert (
        count_hba_lines(text2, "hostssl", "all", "all", "10.0.0.0/8", "scram-sha-256")
        == 1
    )


@pytest.mark.unit
def test_hba_no_network_rule_without_allowed_cidr(tmp_path, bash):
    """
    Without ALLOWED_CIDR/ALLOWED_CIDR_V6 and with ALLOW_NETWORK unset/false,
    apply_hba_policy must only write the four default lines:
      - 2x local (postgres + mapped)
      - 2x loopback (v4/v6)
    """
    hba = tmp_path / "pg_hba.conf"
    hba.touch()

    env = {"HBA": str(hba)}
    r = bash('apply_hba_policy "$HBA"', env=env)
    assert r.rc == 0, r.stderr

    # Count non-empty, non-comment lines inside the managed block (whole file in tests)
    lines = [
        ln
        for ln in hba.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert len(lines) == 4


@pytest.mark.unit
def test_hba_socket_only_rejects_loopback(tmp_path, bash):
    """
    With SOCKET_ONLY=true, loopback TCP must be rejected while local socket
    rules remain. Ensure idempotency across runs.
    """
    hba = tmp_path / "pg_hba.conf"
    hba.touch()

    env = {"HBA": str(hba), "SOCKET_ONLY": "true", "LOCAL_PEER_MAP": "localmap"}
    r1 = bash('apply_hba_policy "$HBA"', env=env)
    assert r1.rc == 0, r1.stderr
    r2 = bash('apply_hba_policy "$HBA"', env=env)
    assert r2.rc == 0, r2.stderr

    text = hba.read_text(encoding="utf-8")
    assert has_hba_line(text, "local", "all", "postgres", "peer")
    assert has_hba_line(text, "local", "all", "all", "peer", "map=localmap")
    assert has_hba_line(text, "host", "all", "all", "127.0.0.1/32", "reject")
    assert has_hba_line(text, "host", "all", "all", "::1/128", "reject")


@pytest.mark.unit
def test_hba_ipv6_allow_with_tls(tmp_path, bash):
    """
    When ALLOWED_CIDR_V6 is provided and TLS is enabled, ensure a hostssl rule
    is written for the IPv6 CIDR and is idempotent.
    """
    hba = tmp_path / "pg_hba.conf"
    hba.touch()

    env = {"HBA": str(hba), "ALLOWED_CIDR_V6": "fd00::/8", "ENABLE_TLS": "true"}
    r1 = bash('apply_hba_policy "$HBA"', env=env)
    assert r1.rc == 0, r1.stderr
    text1 = hba.read_text(encoding="utf-8")
    assert has_hba_line(text1, "hostssl", "all", "all", "fd00::/8", "scram-sha-256")

    r2 = bash('apply_hba_policy "$HBA"', env=env)
    assert r2.rc == 0, r2.stderr
    text2 = hba.read_text(encoding="utf-8")
    assert (
        count_hba_lines(text2, "hostssl", "all", "all", "fd00::/8", "scram-sha-256")
        == 1
    )
