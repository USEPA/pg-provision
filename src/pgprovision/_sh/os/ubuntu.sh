#!/usr/bin/env bash
# Ubuntu 22.04/24.04 + PGDG helpers
set -Eeuo pipefail

_apt_update_once_done="false"
_cnf_hook="/etc/apt/apt.conf.d/50command-not-found"

_disable_cnf_hook() {
  if [[ -f "${_cnf_hook}" ]]; then
    run mv -f "${_cnf_hook}" "${_cnf_hook}.bak.airules" || true
    echo "+ disabled command-not-found APT hook"
  fi
}

_restore_cnf_hook() {
  if [[ -f "${_cnf_hook}.bak.airules" ]]; then
    run mv -f "${_cnf_hook}.bak.airules" "${_cnf_hook}" || true
    echo "+ restored command-not-found APT hook"
  fi
}
_apt_update_once() {
  if [[ "${_apt_update_once_done}" != "true" ]]; then
    # Disable problematic APT post-invoke hook that may import apt_pkg with a mismatched python3.
    _disable_cnf_hook || true
    # Try update with hook suppressed, then fallback to normal update.
    if ! run apt-get -o APT::Update::Post-Invoke-Success= -y update; then
      run apt-get update -y
    fi
    _restore_cnf_hook || true
    _apt_update_once_done="true"
  fi
}

os_prepare_repos() {
  local repo_kind="${1:-pgdg}"
    run apt-get install -y curl ca-certificates gnupg lsb-release
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --yes --batch --dearmor -o /etc/apt/keyrings/postgresql.gpg
    local codename
    codename=$(lsb_release -cs)
    echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list
}

os_install_packages() {
  _apt_update_once
  run apt-get install -y postgresql-16 postgresql-client-16 postgresql-contrib
}

os_init_cluster() {
  local data_dir="${1:-auto}"
  # Ubuntu auto-creates 16 cluster when postgresql-16 is installed via PGDG.
  # Custom data dir requires cluster tooling; enforce availability and success.
  if [[ "$data_dir" != "auto" && -n "$data_dir" ]]; then
    if ! command -v pg_dropcluster >/dev/null 2>&1 || ! command -v pg_createcluster >/dev/null 2>&1; then
      err "pg_dropcluster/pg_createcluster not available; cannot relocate data dir to ${data_dir}"
      exit 2
    fi
    if systemctl is-active --quiet postgresql@16-main; then run systemctl stop postgresql@16-main; fi
    run pg_dropcluster --stop 16 main
    run install -d -m 0700 "$data_dir"
    ubuntu_apparmor_allow_datadir "$data_dir" || true  # defensive: non-fatal on systems without AppArmor
    run pg_createcluster 16 main -d "$data_dir"
  fi
  run systemctl enable --now postgresql@16-main
}

os_get_paths() {
  echo "CONF_FILE=/etc/postgresql/16/main/postgresql.conf HBA_FILE=/etc/postgresql/16/main/pg_hba.conf IDENT_FILE=/etc/postgresql/16/main/pg_ident.conf DATA_DIR=/var/lib/postgresql/16/main SERVICE=postgresql@16-main"
}

os_enable_and_start() {
  local svc="${1:-postgresql@16-main}"
  run systemctl enable --now "$svc"
}

os_restart() {
  local svc="${1:-postgresql@16-main}"
  run systemctl restart "$svc"
}

# Add AppArmor local override for custom data directory and reload profile
ubuntu_apparmor_allow_datadir() {
  local dir="$1"
  # Paths per Ubuntu packaging of PostgreSQL
  local profile="/etc/apparmor.d/usr.lib.postgresql.postgres"
  local local_override="/etc/apparmor.d/local/usr.lib.postgresql.postgres"
  run install -d -m 0755 "$(dirname "$local_override")"
  local rule="  ${dir}/** rwk,"
  run bash -c "printf '%s\n' \"$rule\" >> \"$local_override\""
  if command -v apparmor_parser >/dev/null 2>&1 && [[ -f "$profile" ]]; then
    run apparmor_parser -r "$profile" || warn "apparmor_parser reload failed"
  else
    # Fallback: try service reload
    if systemctl list-units --type=service | grep -q apparmor; then
      # STRICT-TODO: Enforce reload success or surface failure to operator.
      # Defensive rationale:
      # - On some systems, reload may not be supported; best-effort avoids hard failures.
      # Strict rationale:
      # - Without a successful reload, new path permissions aren’t enforced; failing here is clearer.
      run systemctl reload apparmor || true
    fi
  fi
}
