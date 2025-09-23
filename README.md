# pg-provision

Idempotent PostgreSQL provisioning as a Python package wrapping portable shell scripts.

## Install

```
pip install pg-provision
```

## Quick start

Show usage (passthrough to shell script):

```
pgprovision --help
```

Dry run (no privileged operations):

```
pgprovision --dry-run
```

## OS Guides

- Ubuntu: [docs/test-plan-ubuntu.md](docs/test-plan-ubuntu.md)
- RHEL/Rocky/Alma: [docs/test-plan-rhel.md](docs/test-plan-rhel.md)

## Notes

- Linux-only. Commands that modify the system require root or passwordless sudo.
- See the test guides for end-to-end provisioning scenarios.

### Secrets
For non-interactive provisioning without leaking passwords, prefer a file-based secret and avoid passing passwords on the command line:

```
CREATE_PASSWORD_FILE=/run/secrets/pgpass \
pgprovision --create-user app --create-db app
```
This prevents secrets from appearing in argv or logs.
