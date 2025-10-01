# PostgreSQL Provisioner – RHEL/Rocky/Alma Test Guide (pgprovision)

This guide validates the **pg-provision** package on RHEL 8/9 (and Rocky/Alma). It assumes PGDG is used by default. It covers installation, service health, HBA policy, profiles, users/DBs, TLS, relocation, and SELinux/firewalld nuances.

______________________________________________________________________

## 0) Prerequisites

- RHEL 8/9, Rocky 8/9, or Alma 8/9 VM with internet access.
- Willingness to install PostgreSQL 16 (PGDG).
- Install the package (system or venv):
  ```bash
  pip install pg-provision
  # sanity
  pgprovision --help
  ```

**Recommended shell setup**

```bash
sudo -s                           # run tests as root
set -euxo pipefail
```

> If non-root, ensure passwordless sudo and that helpers writing under `$PGDATA` and `/var/lib/pgsql/...` use sudo.
> **Important — CLI behavior:** `pgprovision` prints usage and exits if called with **no arguments**. Environment variables alone do **not** trigger execution. Include at least one flag. This guide uses **CLI flags that mirror defaults** (e.g., `--pg-version 16`) to match `provision.sh` with no args.

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
pgprovision --dry-run | tee ./pgprov_dryrun_rhel.log
# Assert: dry-run must not try to install packages
! grep -qE '(^|[[:space:]])(dnf|yum)[[:space:]]+install([[:space:]]|$)' ./pgprov_dryrun_rhel.log
```

______________________________________________________________________

## 2) Full install (PGDG repo, packages, cluster, service)

The provisioner should:

- Install PGDG repo RPM.
- Disable the AppStream PostgreSQL module.
- Install `postgresql16`, `postgresql16-server`, and `postgresql16-contrib`.
- Initialize and start the service.

Run (include a neutral default flag to trigger execution):

```bash
pgprovision --pg-version 16 | tee ./pgprov_install_rhel.log

systemctl status postgresql-16 --no-pager || true
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SELECT version();"
```

**If service didn’t start:**

```bash
systemctl status postgresql-16 --no-pager -l || true
journalctl -xeu postgresql-16 --no-pager | tail -n 100 || true
# Initialize cluster manually if needed:
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb || true
systemctl enable --now postgresql-16 || true
```

**Paths (PGDG on RHEL)**

- Data dir: `/var/lib/pgsql/16/data`
- Configs: `/var/lib/pgsql/16/data/postgresql.conf` (plus `pg_hba.conf`, `pg_ident.conf`)
- Service: `postgresql-16`

______________________________________________________________________

## 3) HBA policy

```bash
HBA=/var/lib/pgsql/16/data/pg_hba.conf
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA"
```

### Socket‑only posture

```bash
pgprovision --socket-only
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -A2 'socket-only'
```

### Allow networks

```bash
pgprovision --allow-network --allowed-cidr "10.0.0.0/8, 192.168.1.0/24"
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -E '10\.0\.0\.0/8|192\.168\.1\.0/24'
```

> **Note:** Even with HBA allowing remote connections, firewalld/SELinux may still block. See Troubleshooting.

______________________________________________________________________

## 4) Profiles (conf.d drop‑in)

Your provisioner adds `include_dir = 'conf.d'` and writes a drop‑in in the same directory as `postgresql.conf`.

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
DROPIN=/var/lib/pgsql/16/data/conf.d/99-pgprovision.conf
grep -E 'shared_buffers|max_wal_size|track_io_timing' "$DROPIN"
```

______________________________________________________________________

## 5) User and database creation

```bash
pgprovision --create-user devuser --create-password 'pAs$123' --create-db devdb

sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname='devuser';"
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SELECT datname, pg_get_userbyid(datdba) FROM pg_database WHERE datname='devdb';"
```

______________________________________________________________________

## 6) Socket group & local peer map

```bash
ME=$(logname 2>/dev/null || echo "$SUDO_USER")
pgprovision --local-peer-map localmap --local-map-entry "${ME}:dev_role" --unix-socket-group pgclients

getent group pgclients
getent group pgclients | grep -E "(^|,|\\s)${ME}(\\s|,|$)" || true
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SELECT rolname FROM pg_roles WHERE rolname = 'dev_role';"
```

______________________________________________________________________

## 7) TLS guardrail and enablement

### 7.1 Guardrail

```bash
set +e
pgprovision --enable-tls
echo "RC=$?"
set -e
```

### 7.2 Self-signed certs and TLS enablement

```bash
DATA_DIR=/var/lib/pgsql/16/data
install -o postgres -g postgres -m 0700 -d "$DATA_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DATA_DIR/server.key" -out "$DATA_DIR/server.crt" -subj "/CN=localhost" -days 365
chown postgres:postgres "$DATA_DIR/server.crt" "$DATA_DIR/server.key"
chmod 0600 "$DATA_DIR/server.key"

pgprovision --enable-tls
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SHOW ssl;"
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SHOW ssl_min_protocol_version;"
```

______________________________________________________________________

## 8) Custom data directory relocation (SELinux aware)

> Destructive to the default cluster.

```bash
NEW_DATA="/var/lib/pgsql/16/custom-data"
pgprovision --data-dir "$NEW_DATA"
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SHOW data_directory;" | grep -F "$NEW_DATA"
```

**If SELinux blocks startup**, label and restore contexts:

```bash
# install semanage if needed
dnf -y install policycoreutils-python-utils || yum -y install policycoreutils-python

semanage fcontext -a -t postgresql_db_t "${NEW_DATA}(/.*)?"
restorecon -Rv "${NEW_DATA}"

systemctl restart postgresql-16
systemctl is-active --quiet postgresql-16 && echo "service up"
```

______________________________________________________________________

## 9) Stamp file & permissions

```bash
STAMP="${NEW_DATA:-/var/lib/pgsql/16/data}/.pgprovision_provisioned.json"
ls -l "$STAMP"
cat "$STAMP"
```

______________________________________________________________________

## 10) Restart sanity

```bash
systemctl restart postgresql-16
systemctl is-active --quiet postgresql-16 && echo "service up"
sudo -u postgres /usr/pgsql-16/bin/psql -At -c "SELECT 1;"
```

______________________________________________________________________

## Troubleshooting

- **Service didn’t start**:

  ```bash
  systemctl status postgresql-16 --no-pager -l
  journalctl -xeu postgresql-16 --no-pager | tail -n 100
  ```

______________________________________________________________________

## 11) Self-heal: missing/invalid PGDATA (fresh create)

```bash
set -euxo pipefail
PGV=16
# Detect service name (PGDG vs AppStream)
if systemctl list-unit-files --type=service | grep -q "^postgresql-${PGV}\.service"; then
  SVC="postgresql-${PGV}"
else
  SVC="postgresql"
fi

# Simulate missing data dir
systemctl stop "$SVC" 2>/dev/null || true
rm -rf "/var/lib/pgsql/${PGV}/data"

# Provisioner should create and start cleanly
pgprovision --pg-version "${PGV}"
systemctl is-active --quiet "$SVC"
# Pick psql path gracefully
PSQL="$(command -v psql || echo /usr/pgsql-${PGV}/bin/psql)"
sudo -u postgres "$PSQL" -At -c "SELECT 1;"
```

______________________________________________________________________

## 12) Self-heal: adopt existing valid PGDATA

```bash
set -euxo pipefail
PGV=16
# Detect service name (PGDG vs AppStream)
if systemctl list-unit-files --type=service | grep -q "^postgresql-${PGV}\.service"; then
  SVC="postgresql-${PGV}"
else
  SVC="postgresql"
fi
REAL_DATA="/var/lib/pgsql/${PGV}/adopt-me"

# Prepare a valid PGDATA manually
install -o postgres -g postgres -m 0700 -d "$REAL_DATA"
INITDB="$(command -v initdb || echo /usr/pgsql-${PGV}/bin/initdb)"
sudo -u postgres "$INITDB" -D "$REAL_DATA"

# Remove any override so the service points to default initially
rm -f "/etc/systemd/system/${SVC}.service.d/override.conf"
systemctl daemon-reload || true

# Run provisioner; expect adoption (override to REAL_DATA, service up)
pgprovision --pg-version "${PGV}"
systemctl is-active --quiet "$SVC"
PSQL="$(command -v psql || echo /usr/pgsql-${PGV}/bin/psql)"
sudo -u postgres "$PSQL" -At -c "SHOW data_directory;" | grep -Fx "$REAL_DATA"
```

- **SELinux AVC denials** (custom data dir):

  ```bash
  getenforce
  ausearch -m AVC -ts recent || true
  # fix contexts:
  semanage fcontext -a -t postgresql_db_t "/path/to/data(/.*)?"
  restorecon -Rv /path/to/data
  systemctl restart postgresql-16
  ```

- **firewalld blocks remote connections** (if you allowed networks in HBA):

  ```bash
  firewall-cmd --add-service=postgresql --permanent
  firewall-cmd --reload
  # or:
  firewall-cmd --add-port=5432/tcp --permanent && firewall-cmd --reload
  ```

- **Permission denied writing under `$PGDATA`**: run as root or ensure helpers use sudo for writes under `/var/lib/pgsql/16/data`.

______________________________________________________________________

## Cleanup (optional)

```bash
systemctl stop postgresql-16 || true
dnf -y remove postgresql16\* || yum -y remove postgresql16\*
rm -rf /var/lib/pgsql /etc/yum.repos.d/pgdg-redhat-all.repo /var/log/pgsql
# If you installed the PGDG repo RPM explicitly and want to remove it:
rpm -qa | grep -i pgdg | xargs -r dnf -y remove || true
groupdel pgclients || true
```

______________________________________________________________________

**End of guides.**
