# PostgreSQL Provisioner – Ubuntu Test Guide (pgprovision)

This guide validates the **pg-provision** package on Ubuntu 22.04/24.04 using the PGDG repository. It covers installation, service health, HBA policy, profiles, users/DBs, TLS, and data directory relocation.

______________________________________________________________________

## 0) Prerequisites

- Ubuntu VM with internet access.
- Willingness to install PostgreSQL 16 (PGDG).
- Install the package (system or venv):

```bash
  pip install pg-provision
  # sanity
  pgprovision --help

  or

  python -m venv .venv && . .venv/bin/activate
  python -m pip install -e .
  pgprovision --dry-run
```

**Recommended shell setup**

```bash
sudo -s                                 # run tests as root for a quiet session
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
```

> Non-root runs require passwordless sudo and helpers that use sudo for writes under `/etc/postgresql/...`.
> **Important — CLI behavior:** `pgprovision` prints usage and exits if called with **no arguments**. Environment variables alone do **not** trigger execution. Include at least one flag in every call. This guide uses **CLI flags that mirror the shell defaults** (e.g., `--pg-version 16`) so behavior matches `provision.sh` with no args.

**CLI ⇄ Env quick map**

- `--socket-only` ⇄ `SOCKET_ONLY=true`
- `--allow-network` ⇄ `ALLOW_NETWORK=true`
- `--allowed-cidr` / `--allowed-cidr-v6` ⇄ `ALLOWED_CIDR` / `ALLOWED_CIDR_V6`
- `--profile NAME` ⇄ `PROFILE=NAME`
- `--enable-tls` ⇄ `ENABLE_TLS=true`
- `--data-dir PATH|auto` ⇄ `DATA_DIR=...`
- `--create-user/--create-db/--create-password` ⇄ `CREATE_USER/CREATE_DB/CREATE_PASSWORD` (prefer `CREATE_PASSWORD_FILE` for secrets)

______________________________________________________________________

## 1) Dry‑run smoke test

```bash
pgprovision --dry-run | tee ./pgprov_dryrun.log
# Assert: dry-run must not try to install packages
! grep -qE '(^|[[:space:]])apt(-get)?[[:space:]]+install([[:space:]]|$)' ./pgprov_dryrun.log
```

**Expect:** note that provisioning is for Ubuntu and **no** `apt install` lines executed.

______________________________________________________________________

## 2) Full install (PGDG repo, packages, cluster, service)

Use an explicit default flag to trigger execution without changing behavior:

```bash
pgprovision --pg-version 16 | tee ./pgprov_install.log

systemctl status postgresql@16-main --no-pager || true
psql --version
sudo -u postgres psql -At -c "SELECT version();"
```

**If service didn’t start:**

```bash
systemctl status postgresql@16-main --no-pager -l || true
journalctl -xeu postgresql@16-main --no-pager | tail -n 100 || true
pg_lsclusters || true
sudo pg_createcluster 16 main || true
sudo pg_ctlcluster 16 main start || true
```

______________________________________________________________________

## 3) HBA policy

### 3.1 View managed block

```bash
HBA=/etc/postgresql/16/main/pg_hba.conf
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA"
```

### 3.2 Socket‑only posture

```bash
pgprovision --socket-only
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -A2 'socket-only'
```

### 3.3 Allow networks

```bash
pgprovision --allow-network --allowed-cidr "10.0.0.0/8, 192.168.1.0/24"
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -E '10\.0\.0\.0/8|192\.168\.1\.0/24'
```

> Server still binds `listen_addresses=localhost` by default; this section validates HBA only.

______________________________________________________________________

## 4) Profiles (conf.d drop‑in)

```bash
mkdir -p profiles
cat >profiles/xl-32c-256g.conf <<'EOF'
shared_buffers=64GB
effective_cache_size=192GB
work_mem=32MB
maintenance_work_mem=2GB
wal_buffers=16MB
max_wal_size=32GB
checkpoint_completion_target=0.9
default_statistics_target=250
track_io_timing=on
EOF

pgprovision --profile xl-32c-256g
DROPIN=/etc/postgresql/16/main/conf.d/99-pgprovision.conf
grep -E 'shared_buffers|max_wal_size|track_io_timing' "$DROPIN"
```

______________________________________________________________________

## 5) User and database creation

```bash
pgprovision --create-user devuser --create-password 'pAs$123' --create-db devdb

sudo -u postgres psql -At -c "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname='devuser';"
sudo -u postgres psql -At -c "SELECT datname, pg_get_userbyid(datdba) FROM pg_database WHERE datname='devdb';"
```

> For non-interactive secrets:\
> `CREATE_PASSWORD_FILE=/run/secrets/pgpass pgprovision --create-user dev --create-db dev`

______________________________________________________________________

## 6) Socket group & local peer map

```bash
ME=$(logname 2>/dev/null || echo "$SUDO_USER")
pgprovision --local-peer-map localmap --local-map-entry "${ME}:dev_role" --unix-socket-group pgclients

getent group pgclients
getent group pgclients | grep -E "(^|,|\\s)${ME}(\\s|,|$)" || true
sudo -u postgres psql -At -c "SELECT rolname FROM pg_roles WHERE rolname = 'dev_role';"
```

> Your current shell may not reflect new group membership until you re‑login. `getent` confirms membership.

______________________________________________________________________

## 7) TLS guardrail and enablement

### 7.1 Guardrail (should fail without cert/key)

```bash
set +e
pgprovision --enable-tls
echo "RC=$?"
set -e
```

### 7.2 Self-signed certs and TLS enablement

```bash
DATA_DIR=$(sudo -u postgres psql -At -c "SHOW data_directory;")
install -o postgres -g postgres -m 0700 -d "$DATA_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DATA_DIR/server.key" -out "$DATA_DIR/server.crt" -subj "/CN=localhost" -days 365
chown postgres:postgres "$DATA_DIR/server.crt" "$DATA_DIR/server.key"
chmod 0600 "$DATA_DIR/server.key"

pgprovision --enable-tls
sudo -u postgres psql -At -c "SHOW ssl;"
sudo -u postgres psql -At -c "SHOW ssl_min_protocol_version;"
```

______________________________________________________________________

## 8) Custom data directory relocation

> Destructive to the default `main` cluster.

```bash
NEW_DATA="/var/lib/postgresql/16/custom-data"
pgprovision --data-dir "$NEW_DATA"
sudo -u postgres psql -At -c "SHOW data_directory;" | grep -F "$NEW_DATA"
```

______________________________________________________________________

## 9) Stamp file & permissions

```bash
STAMP=$(sudo -u postgres psql -At -c "SHOW data_directory;")/.pgprovision_provisioned.json
ls -l "$STAMP"
cat "$STAMP"
```

______________________________________________________________________

## 10) Restart sanity

```bash
systemctl restart postgresql@16-main
systemctl is-active --quiet postgresql@16-main && echo "service up"
sudo -u postgres psql -At -c "SELECT 1;"
```

______________________________________________________________________

## Troubleshooting

- **`tee: Permission denied`**: remove root‑owned file or tee to a path you own:

  ```bash
  sudo rm -f /tmp/pgprov_install.log
  pgprovision --pg-version 16 | tee ./pgprov_install.log
  # or:
  pgprovision --pg-version 16 | sudo tee /tmp/pgprov_install.log >/dev/null
  ```

- **Service didn’t start**:

  ```bash
  systemctl status postgresql@16-main --no-pager -l
  journalctl -xeu postgresql@16-main --no-pager | tail -n 100
  pg_lsclusters
  sudo pg_createcluster 16 main || true
  sudo pg_ctlcluster 16 main start || true
  ```

- **PGDG key error** (`NO_PUBKEY …ACCC4CF8`): ensure `/etc/apt/keyrings/postgresql.gpg` exists and is world‑readable (`chmod 0644`). Re-run `apt-get update`.

- **Permission denied writing `/etc/postgresql/...`**: run as root or ensure helpers use sudo for writes.

______________________________________________________________________

## Cleanup (optional)

```bash
apt-get purge -y "postgresql-16*" "postgresql-client-16*" postgresql-contrib
rm -f /etc/apt/sources.list.d/pgdg.list /etc/apt/keyrings/postgresql.gpg
apt-get autoremove -y
rm -rf /var/lib/postgresql /etc/postgresql /var/log/postgresql
groupdel pgclients || true
```

______________________________________________________________________

## Provisioning Idempotency Testing (Ubuntu)

*Proves we can re-run provisioning without breaking anything (idempotent, no drift).*

# Run as root or with sudo.

```bash
set -euxo pipefail
trap 'echo "--- $UNIT (tail) ---"; journalctl -u "$UNIT" --no-pager | tail -n 80 || true' ERR

PGV=16
CL=main
UNIT="postgresql@${PGV}-${CL}"
HBA="/etc/postgresql/${PGV}/${CL}/pg_hba.conf"
DROPIN="/etc/postgresql/${PGV}/${CL}/conf.d/99-pgprovision.conf"
PGDG_LIST="/etc/apt/sources.list.d/pgdg.list"
KEYRING="/etc/apt/keyrings/postgresql.gpg"
NEW_DATA="/var/lib/postgresql/${PGV}/custom-data"

# Capture identity to detect accidental reinit
sysid_before=$(sudo -u postgres psql -At -c "SELECT system_identifier FROM pg_control_system();")

# 1) Base install should be stable (idempotent)
sudo pgprovision --pg-version "${PGV}"

# 2) HBA posture: socket-only -> allow network -> back to socket-only
sudo pgprovision --socket-only
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -F 'socket-only'

sudo pgprovision --allow-network --allowed-cidr "127.0.0.1/32"
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -F '127.0.0.1/32'

sudo pgprovision --socket-only
# Ensure exactly one managed block (no dupes)
test "$(grep -Fc "# pgprovision:hba begin (managed)" "$HBA")" -eq 1

# 3) Profile apply should be idempotent
sudo pgprovision --profile xl-32c-256g
grep -E 'shared_buffers|track_io_timing' "$DROPIN"
sha1_before=$(sha1sum "$DROPIN" | awk '{print $1}')
sudo pgprovision --profile xl-32c-256g
sha1_after=$(sha1sum "$DROPIN" | awk '{print $1}')
test "$sha1_before" = "$sha1_after"

# 4) TLS guardrail: expect non-zero RC without cert/key, but keep the service alive
set +e
sudo pgprovision --enable-tls
rc=$?
set -e
echo "enable-tls RC=$rc (expected non-zero without cert/key)"
systemctl is-active --quiet "$UNIT" || sudo systemctl restart "$UNIT"
sudo -u postgres psql -At -c "SELECT 1;"

# 5) Data directory relocation (idempotent when path is unchanged)
sudo pgprovision --data-dir "$NEW_DATA"
sudo -u postgres psql -At -c "SHOW data_directory;" | grep -Fx "$NEW_DATA"

# 6) Invariants
test -r "$KEYRING"
grep -Fq "https://apt.postgresql.org" "$PGDG_LIST"
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" >/dev/null
sudo -u postgres psql -At -c "SHOW listen_addresses;" | grep -Fx 'localhost'
# If you *intend* to preload pg_stat_statements, assert it. Otherwise leave this commented.
# sudo -u postgres psql -At -c "SHOW shared_preload_libraries;" | grep -Fq pg_stat_statements

# 7) Cluster identity unchanged ⇒ no reinit
sysid_after=$(sudo -u postgres psql -At -c "SELECT system_identifier FROM pg_control_system();")
test "$sysid_before" = "$sysid_after"
```

______________________________________________________________________

## 11) Self-heal: broken metadata, missing datadir

```bash
set -euxo pipefail
PGV=16
UNIT="postgresql@${PGV}-main"
sudo systemctl stop "$UNIT" 2>/dev/null || true

# Simulate the mess: config exists (wrong owner), data dir missing
sudo install -d -m 0700 -o root -g root "/etc/postgresql/${PGV}/main"
echo "# minimal" | sudo tee "/etc/postgresql/${PGV}/main/postgresql.conf" >/dev/null
sudo rm -rf "/var/lib/postgresql/${PGV}/main"

# Should self-heal without manual steps (default behavior):
sudo pgprovision --pg-version "${PGV}"

# Validate: cluster present, service up, conf owned by postgres
pg_lsclusters
systemctl is-active --quiet "$UNIT"
stat -c '%U:%G' "/etc/postgresql/${PGV}/main/postgresql.conf" | grep -Fx 'postgres:postgres'
sudo -u postgres psql -At -c "SELECT 1;"
```

______________________________________________________________________

## 12) Self-heal: adopt existing valid PGDATA

```bash
set -euxo pipefail
PGV=16
UNIT="postgresql@${PGV}-main"
REAL_DATA="/var/lib/postgresql/${PGV}/adopt-me"

# Prepare a valid PGDATA manually
sudo install -d -m 0700 -o postgres -g postgres "$REAL_DATA"
/usr/lib/postgresql/${PGV}/bin/initdb -D "$REAL_DATA" -U postgres

# Remove metadata to simulate haunted state
sudo systemctl stop "$UNIT" 2>/dev/null || true
sudo rm -rf "/etc/postgresql/${PGV}/main"

# Run provisioner; expect adoption (metadata rebuilt to point at REAL_DATA)
sudo pgprovision --pg-version "${PGV}"

# Validate: service up and we can connect
systemctl is-active --quiet "$UNIT"
sudo -u postgres psql -At -c "SELECT 1;"
```
