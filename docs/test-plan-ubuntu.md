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
  ```

**Recommended shell setup**

```bash
sudo -s                                 # run tests as root for a quiet session
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
```

> Non-root runs require passwordless sudo and helpers that use sudo for writes under `/etc/postgresql/...`.

______________________________________________________________________

## 1) Dry‑run smoke test

```bash
pgprovision --dry-run | tee ./pgprov_dryrun.log
# Assert: dry-run must not try to install packages
! grep -qE '(^|[[:space:]])apt(-get)?[[:space:]]+install([[:space:]]|$)' ./pgprov_dryrun.log
```

**Expect:** clear note that provisioning is for Ubuntu and **no** `apt install` lines executed.

______________________________________________________________________

## 2) Full install (PGDG repo, packages, cluster, service)

```bash
pgprovision | tee ./pgprov_install.log

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
SOCKET_ONLY=true pgprovision
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -A2 'socket-only'
```

### 3.3 Allow networks

```bash
ALLOW_NETWORK=true ALLOWED_CIDR="10.0.0.0/8, 192.168.1.0/24" pgprovision
awk '/^# pgprovision:hba begin \(managed\)/,/^# pgprovision:hba end/' "$HBA" | grep -E '10\.0\.0\.0/8|192\.168\.1\.0/24'
```

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

PROFILE=xl-32c-256g pgprovision
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
ENABLE_TLS=true pgprovision
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

ENABLE_TLS=true pgprovision
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
  pgprovision | tee ./pgprov_install.log
  # or:
  pgprovision | sudo tee /tmp/pgprov_install.log >/dev/null
  ```

- **Service didn’t start**:

  ```bash
  systemctl status postgresql@16-main --no-pager -l
  journalctl -xeu postgresql@16-main --no-pager | tail -n 100
  pg_lsclusters
  sudo pg_createcluster 16 main || true
  sudo pg_ctlcluster 16 main start || true
  ```

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
