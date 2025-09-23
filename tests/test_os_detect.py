"""
Unit tests for os_detect via OS_RELEASE_PATH injection.
"""

import pytest


@pytest.mark.unit
def test_os_detect_ubuntu(tmp_path, bash):
    osrel = tmp_path / "os-release"
    osrel.write_text(
        "\n".join(
            [
                "ID=ubuntu",
                "ID_LIKE=debian",
                "VERSION_ID=24.04",
                "UBUNTU_CODENAME=noble",
            ]
        ),
        encoding="utf-8",
    )
    env = {"OS_RELEASE_PATH": str(osrel)}
    r = bash('os_detect; echo "$OS_FAMILY"', env=env)
    assert r.rc == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == "ubuntu"


@pytest.mark.unit
def test_os_detect_rhel_like(tmp_path, bash):
    osrel = tmp_path / "os-release"
    osrel.write_text(
        'ID=rocky\nID_LIKE="rhel fedora"\nVERSION_ID=9\n', encoding="utf-8"
    )
    env = {"OS_RELEASE_PATH": str(osrel)}
    r = bash('os_detect; echo "$OS_FAMILY"', env=env)
    assert r.rc == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == "rhel"


@pytest.mark.unit
def test_os_detect_unsupported(tmp_path, bash):
    osrel = tmp_path / "os-release"
    osrel.write_text('ID=foo\nID_LIKE="bar baz"\n', encoding="utf-8")
    env = {"OS_RELEASE_PATH": str(osrel)}
    r = bash("os_detect", env=env)
    assert r.rc != 0
