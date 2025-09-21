#!/usr/bin/env bash
set -Eeuo pipefail

# Internal helpers (AppStream-only: service=postgresql, PGDATA=/var/lib/pgsql/data)
_rhel_service_name() { echo postgresql; }
_rhel_default_pgdata_for_service() { echo /var/lib/pgsql/data; }

_rhel_set_pgdata_override() {
  local svc="${1:?svc}" pgdata="${2:?pgdata}"
  local dropin="/etc/systemd/system/${svc}.service.d/override.conf"
  mkdir -p "$(dirname "$dropin")"
  cat >"$dropin" <<OVR
[Service]
Environment=PGDATA=${pgdata}
OVR
  run systemctl daemon-reload
}

_rhel_selinux_label_datadir() {
  local dir="${1:?dir}"
  if ! command -v semanage >/dev/null 2>&1; then
    err "SELinux management tools not available. Install policycoreutils-python-utils or run on permissive hosts."
    return 1
  fi
  if ! semanage fcontext -a -t postgresql_db_t "${dir}(/.*)?" 2>/dev/null; then
    if ! semanage fcontext -m -t postgresql_db_t "${dir}(/.*)?" 2>/dev/null; then
      err "Failed to set SELinux context for PostgreSQL data directory: ${dir}"
      return 1
    fi
  fi
  run restorecon -Rv "${dir}"
}

os_prepare_repos() {
  run dnf -y module reset postgresql
  run dnf -y module enable postgresql:16
}

os_install_packages() {
  # AppStream 16: server + client + contrib
  run dnf -y install postgresql postgresql-server postgresql-contrib
}

os_init_cluster() {
  local data_dir="${1:-auto}"
  if [[ "$data_dir" == "auto" ]]; then
    if [[ ! -d /var/lib/pgsql/data/base ]]; then
      run postgresql-setup --initdb
    fi
    run systemctl enable --now postgresql
  else
    run install -d -m 0700 "$data_dir"
    run chown -R postgres:postgres "$data_dir"
    run chmod 700 "$data_dir"
    _rhel_selinux_label_datadir "$data_dir" || true
    if command -v initdb >/dev/null 2>&1; then
      if [[ ! -d "$data_dir/base" ]]; then
        run sudo -u postgres initdb -D "$data_dir"
      fi
    else
      err "initdb not found; cannot initialize custom data dir at ${data_dir}"
      exit 2
    fi
    _rhel_set_pgdata_override postgresql "$data_dir"
    run systemctl enable --now postgresql
  fi
}

os_get_paths() {
  local svc="postgresql" pgdata="/var/lib/pgsql/data" override
  override="/etc/systemd/system/${svc}.service.d/override.conf"
  if [[ -f "$override" ]] && grep -q '^Environment=PGDATA=' "$override"; then
    pgdata=$(sed -n 's/^Environment=PGDATA=\(.*\)$/\1/p' "$override" | tail -n1)
  fi
  echo "CONF_FILE=${pgdata}/postgresql.conf HBA_FILE=${pgdata}/pg_hba.conf IDENT_FILE=${pgdata}/pg_ident.conf DATA_DIR=${pgdata} SERVICE=${svc}"
}

os_enable_and_start() {
  local svc="${1:-$(_rhel_service_name)}"
  run systemctl enable --now "$svc"
}

os_restart() {
  local svc="${1:-$(_rhel_service_name)}"
  run systemctl restart "$svc"
}
