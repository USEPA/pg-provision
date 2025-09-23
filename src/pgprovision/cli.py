import argparse
import os
import subprocess
from importlib import resources
from importlib import metadata as _md


def _script_path(name: str) -> str:
    return str(resources.files("pgprovision._sh").joinpath(name))


def _needs_root(passthrough_args):
    if os.geteuid() == 0:
        return False
    args = set(passthrough_args or [])
    return not ({"--help", "-h", "--dry-run"} & args)


def _run_script(script_rel: str, passthrough_args):
    script = _script_path(script_rel)
    base = ["/usr/bin/env", "bash", script] + list(passthrough_args or [])
    cmd = (["sudo", "-n", "--"] + base) if _needs_root(passthrough_args) else base
    # Preserve current env; let the bash scripts parse flags/env-files
    proc = subprocess.run(cmd)
    return proc.returncode


def main(argv=None):
    # Passthrough CLI: we only parse a couple of meta-flags; everything else goes to the shell script.
    parser = argparse.ArgumentParser(
        prog="pgprovision",
        add_help=False,
        description="PostgreSQL idempotent provisioner",
    )
    # We don't duplicate the shell flags; we just forward them verbatim.
    parser.add_argument(
        "--help", "-h", action="store_true", help="Show shell script help"
    )
    parser.add_argument(
        "--version", action="store_true", help="Show package version and exit"
    )
    args, rest = parser.parse_known_args(argv)

    if args.version:
        ver = "unknown"
        for dist in ("pg-provision", "pgprovision"):
            try:
                ver = _md.version(dist)
                break
            except _md.PackageNotFoundError:
                continue
        print(ver)
        return 0

    if args.help or (argv is None and not rest):
        # Show the shell script's usage
        return _run_script("provision.sh", ["--help"])

    return _run_script("provision.sh", rest)
