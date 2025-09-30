# pg-provision

[![PyPI - Version](https://img.shields.io/pypi/v/pg-provision.svg)](https://pypi.org/project/pg-provision/) [![Python Versions](https://img.shields.io/pypi/pyversions/pg-provision.svg)](https://pypi.org/project/pg-provision/)

Idempotent PostgreSQL provisioning as a Python package wrapping portable shell scripts.

## Install

```
pip install pg-provision
```

## Quick start

Show usage (pass‑through to shell script):

```bash
pgprovision --help
```

Dry run (no privileged operations):

```bash
pgprovision --dry-run
```

> Root or passwordless sudo is required for changes. The CLI auto‑invokes `sudo -n` when needed.

## Common scenarios (copy/paste)

### 1) **Hardened (RHEL/Rocky/Alma): socket‑only, local peer auth**

No TCP listener; UNIX socket is gated by a dedicated group; OS users are mapped to DB roles via `pg_ident`. Good default for single‑host services.

```bash
pgprovision \
  --repo pgdg \
  --listen-addresses '' \
  --socket-only \
  --unix-socket-group pgclients \
  --unix-socket-permissions 0770 \
  --local-peer-map localmap \
  --local-map-entry alice:app_rw \
  --local-map-entry bob:analytics \
  --admin-group-role dba_group \
  --admin-dbrole dba
```

**Notes**

- `--listen-addresses ''` disables TCP; only UNIX sockets are used.
- `--unix-socket-group` controls who can connect locally; members are added automatically.
- `--local-map-entry OSUSER:DBROLE` writes `pg_ident.conf` and ensures DB roles exist.
- Optional safety switch once your admin path works:

```bash
pgprovision --disable-postgres-login
```

______________________________________________________________________

### 2) **Hardened (RHEL/Rocky/Alma): loopback‑only TCP (localhost)**

Keep TCP on `127.0.0.1`/`::1` only; pair with peer mappings (for local tooling) or layer your own auth later.

```bash
pgprovision \
  --repo pgdg \
  --listen-addresses localhost \
  --port 5432 \
  --local-peer-map localmap \
  --local-map-entry serviceuser:service_role
```

______________________________________________________________________

### 3) **Permissive (Ubuntu): listen on all interfaces for a trusted LAN**

Opens the server to a private IPv4 range (add IPv6 if needed). This example **does not** create credentials; bring your own auth model.

```bash
pgprovision \
  --repo pgdg \
  --listen-addresses '*' \
  --allowed-cidr 192.168.0.0/16 \
  --allow-network
```

Add IPv6:

```bash
pgprovision \
  --repo pgdg \
  --listen-addresses '*' \
  --allowed-cidr 192.168.0.0/16 \
  --allowed-cidr-v6 'fd00::/8' \
  --allow-network
```

> Network exposure without an explicit auth strategy is risky. Use this only on trusted networks and add your own authentication/authorization controls.

______________________________________________________________________

### 4) **TLS‑required server (certs pre‑positioned)**

Enables TLS. The script fails early if `server.crt`/`server.key` are absent in the active `data_directory`.

```bash
pgprovision \
  --repo pgdg \
  --listen-addresses '*' \
  --allowed-cidr 10.0.0.0/8 \
  --allow-network \
  --enable-tls
```

______________________________________________________________________

### 5) **Reproducible runs via env‑file (no secrets)**

Keep knobs in a file. Any flag‑backed var can live here.

`/etc/pgprovision.env`:

```bash
PG_VERSION=16
REPO_KIND=pgdg
LISTEN_ADDRESSES=localhost
PORT=5432
ALLOW_NETWORK=false
```

Run:

```bash
pgprovision --env-file /etc/pgprovision.env
```

(You can still pass additional flags on the command line for things like peer mappings.)

______________________________________________________________________

### 6) **Custom data directory + pg_stat_statements**

```bash
pgprovision \
  --repo pgdg \
  --data-dir /data/postgres/16/main \
  --init-pg-stat-statements
```

After restart, the script attempts `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;`.

______________________________________________________________________

## OS Guides

- Ubuntu: [docs/test-plan-ubuntu.md](docs/test-plan-ubuntu.md)
- RHEL/Rocky/Alma: [docs/test-plan-rhel.md](docs/test-plan-rhel.md)

### Self‑Heal on Ubuntu (PGDG)

On Ubuntu/Debian with PGDG, packaging normally creates a default `main` cluster. If that metadata is broken (e.g., `pg_lsclusters` errors, `/etc/postgresql/<ver>/main` owned by root, or `data_directory` missing), pg‑provision can self‑heal before applying HBA/profile/role changes.

- Non‑destructive: it never deletes a directory that looks like a real PGDATA (has `PG_VERSION` and `global/pg_control`).
- If a valid PGDATA exists, it rebuilds Debian metadata to point at it (adoption), then starts the service.
- Default behavior is on; disable with `--no-self-heal` or `SELF_HEAL=false`.
- See `docs/test-plan-ubuntu.md` for self‑heal scenarios.

### Self‑Heal on RHEL (PGDG)

On RHEL family (RHEL/Rocky/Alma/Fedora/Amazon Linux), the provisioner preflights the cluster and will adopt an existing valid `PGDATA` by setting a systemd override (`Environment=PGDATA=…`) and ensuring permissions/SELinux context. If no valid data exists, it initializes a fresh cluster using packaging helpers (`postgresql-setup`) or `initdb`.

- Non‑destructive: never deletes a directory that looks like a real PGDATA.
- See `docs/test-plan-rhel.md` for self‑heal scenarios.

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

## Project Links

- PyPI: https://pypi.org/project/pg-provision/
- Release 0.2.4: https://pypi.org/project/pg-provision/0.2.4/
