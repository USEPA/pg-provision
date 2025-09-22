#!/usr/bin/env bash
    # RHEL/Rocky/Alma helpers for PostgreSQL with PGDG or AppStream repos
    set -Eeuo pipefail

    # Expect these from the caller: run(), err(), and variables PG_VERSION, REPO_KIND
    : "${PG_VERSION:=16}"
    : "${REPO_KIND:=pgdg}"

    _rhel_service_name() {
      # Determine service name after packages are installed
      if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^postgresql-${PG_VERSION}\.service"; then
        echo "postgresql-${PG_VERSION}"
      else
        echo "postgresql"
      fi
    }

    _rhel_default_pgdata_for_service() {
      local svc="$(_rhel_service_name)"
      if [[ "$svc" =~ postgresql-[0-9]+ ]]; then
        echo "/var/lib/pgsql/${PG_VERSION}/data"
      else
        echo "/var/lib/pgsql/data"
      fi
    }

    _rhel_set_pgdata_override() {
      local svc="${1:?svc}" pgdata="${2:?pgdata}"
      local dropin="/etc/systemd/system/${svc}.service.d/override.conf"
      mkdir -p "$(dirname "$dropin")"
      cat >"$dropin" <<OVR
[Unit]
RequiresMountsFor=${pgdata}

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
      local repo_kind="${1:-${REPO_KIND}}"
      if [[ "$repo_kind" == "pgdg" ]]; then
        # Use PGDG and disable AppStream module
        run dnf -y module reset postgresql || true
        run dnf -y module disable postgresql || true
        local rpm_url="https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %rhel)-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
        run dnf -y install "$rpm_url"
      else
        # Use OS AppStream module at the requested major version
        run dnf -y module reset postgresql || true
        run dnf -y module enable "postgresql:${PG_VERSION}"
      fi
    }

    os_install_packages() {
      local repo_kind="${1:-${REPO_KIND}}"
      if [[ "$repo_kind" == "pgdg" ]]; then
        run dnf -y install "postgresql${PG_VERSION}" "postgresql${PG_VERSION}-server" "postgresql${PG_VERSION}-contrib"
      else
        run dnf -y install postgresql postgresql-server postgresql-contrib
      fi
    }

    os_init_cluster() {
      local data_dir="${1:-auto}"
      local svc="$(_rhel_service_name)"
      # Choose setup command depending on packaging
      local setup_cmd=""
      if command -v postgresql-setup >/dev/null 2>&1 && [[ "$svc" == "postgresql" ]]; then
        setup_cmd="postgresql-setup --initdb"
      elif [[ -x "/usr/pgsql-${PG_VERSION}/bin/postgresql-${PG_VERSION}-setup" ]]; then
        setup_cmd="/usr/pgsql-${PG_VERSION}/bin/postgresql-${PG_VERSION}-setup initdb"
      fi

      if [[ "$data_dir" == "auto" ]]; then
        if [[ -n "$setup_cmd" ]]; then
          run $setup_cmd
        else
          # Fallback to initdb if setup helper unavailable
          local pgdata="$(_rhel_default_pgdata_for_service)"
          run install -d -m 0700 "$pgdata"
          run chown -R postgres:postgres "$pgdata"
          run sudo -u postgres initdb -D "$pgdata"
        fi
        run systemctl enable --now "$svc"
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
        _rhel_set_pgdata_override "$svc" "$data_dir"
        run systemctl enable --now "$svc"
      fi
    }

    os_get_paths() {
      local svc="$(_rhel_service_name)"
      local pgdata="$(_rhel_default_pgdata_for_service)"
      local override="/etc/systemd/system/${svc}.service.d/override.conf"
      if [[ -f "$override" ]] && grep -q '^Environment=PGDATA=' "$override"; then
        pgdata=$(sed -n 's/^Environment=PGDATA=\(.*\)$/\1/p' "$override" | tail -n1)
      fi
      echo "CONF_FILE=${pgdata}/postgresql.conf HBA_FILE=${pgdata}/pg_hba.conf IDENT_FILE=${pgdata}/pg_ident.conf DATA_DIR=${pgdata} SERVICE=${svc}"
    }

    os_enable_and_start() {
      local svc="$(_rhel_service_name)"
      run systemctl enable --now "$svc"
    }

    os_restart() {
      local svc="$(_rhel_service_name)"
      run systemctl restart "$svc"
    }
