import os
from types import SimpleNamespace

import pgprovision.cli as cli


class DummyProc(SimpleNamespace):
    def __init__(self, returncode=0):
        super().__init__(returncode=returncode)


def test_cli_no_sudo_for_help(monkeypatch):
    calls = {}

    def fake_run(cmd, *args, **kwargs):
        calls["cmd"] = cmd
        return DummyProc(0)

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._run_script("provision.sh", ["--help"])  # type: ignore[arg-type]
    assert rc == 0
    assert calls["cmd"][0] == "/usr/bin/env"
    assert "sudo" not in calls["cmd"]


def test_cli_no_sudo_for_dry_run(monkeypatch):
    calls = {}

    def fake_run(cmd, *args, **kwargs):
        calls["cmd"] = cmd
        return DummyProc(0)

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._run_script("provision.sh", ["--dry-run"])  # type: ignore[arg-type]
    assert rc == 0
    assert calls["cmd"][0] == "/usr/bin/env"
    assert "sudo" not in calls["cmd"]


def test_cli_uses_sudo_for_actions(monkeypatch):
    calls = {}

    def fake_run(cmd, *args, **kwargs):
        calls["cmd"] = cmd
        return DummyProc(0)

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    rc = cli._run_script("provision.sh", ["--repo", "pgdg"])  # type: ignore[arg-type]
    assert rc == 0
    assert calls["cmd"][0] == "sudo"
