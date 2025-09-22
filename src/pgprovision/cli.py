import argparse
import os
import subprocess
from importlib import resources


def _script_path(name: str) -> str:
    # resolve script from package data
    return str(resources.files("pgprov._sh").joinpath(name))


def _ensure_root(cmd):
    # If not root, try to run with sudo -n (non-interactive). Fall back to direct exec if already root.
    if os.geteuid() == 0:
        return cmd
    return ["sudo", "-n", "--"] + cmd


def _run_script(script_rel: str, passthrough_args):
    script = _script_path(script_rel)
    cmd = _ensure_root(["/usr/bin/env", "bash", script] + passthrough_args)
    # Preserve current env; let the bash scripts parse flags/env-files
    proc = subprocess.run(cmd)
    return proc.returncode


def main(argv=None):
    # Passthrough CLI: we only parse a couple of meta-flags; everything else goes to the shell script.
    parser = argparse.ArgumentParser(
        prog="pgprov", add_help=False, description="PostgreSQL idempotent provisioner"
    )
    # We don't duplicate the shell flags; we just forward them verbatim.
    parser.add_argument(
        "--help", "-h", action="store_true", help="Show shell script help"
    )
    args, rest = parser.parse_known_args(argv)

    if args.help:
        # Show the shell script's usage
        return _run_script("provision.sh", ["--help"])

    return _run_script("provision.sh", rest)
