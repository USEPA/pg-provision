#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=src/pgprovision/_sh/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

# shellcheck source=src/pgprovision/_sh/lib/hba.sh
. "${SCRIPT_DIR}/lib/hba.sh"

require_root_or_sudo() {
  if [[ $(id -u) -eq 0 ]]; then return 0; fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then return 0; fi
  err "This script needs root or passwordless sudo (sudo -n)."
  exit 1
}

readonly -a RHEL_IDS=(rhel rocky almalinux centos ol oraclelinux amzn fedora redhat)
readonly -a DEB_IDS=(ubuntu debian linuxmint pop neon zorin raspbian kali elementary)

# Match any whole-word token in $1 against the remaining args.
# Uses the " space $hay space " trick for word boundaries; RHEL7-safe (no declare -n).
has_any_token() {
  local hay=" $1 " t
  shift
  for t in "$@"; do
    [[ "$hay" == *" $t "* ]] && return 0
  done
  return 1
}

os_detect() {
  local osrel="${OS_RELEASE_PATH:-/etc/os-release}"
  [[ -r "$osrel" ]] || { err "$osrel not found"; exit 2; }
  # shellcheck disable=SC1091
  . "$osrel"

  OS_VERSION_ID="${VERSION_ID:-}"
  OS_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"

  local tokens="${ID:-} ${ID_LIKE:-}"
  if   has_any_token "$tokens" "${RHEL_IDS[@]}"; then OS_FAMILY="rhel"
  elif has_any_token "$tokens" "${DEB_IDS[@]}";  then OS_FAMILY="ubuntu"
  else
    err "Unsupported OS: ID=${ID:-unknown} ID_LIKE=${ID_LIKE:-}"; exit 2
  fi
}

load_os_module() {
  local file="${SCRIPT_DIR}/os/${OS_FAMILY}.sh"
  [[ -r "$file" ]] || { err "Missing module: $file"; exit 2; }

  # shellcheck source=src/pgprovision/_sh/os/rhel.sh
  # shellcheck source=src/pgprovision/_sh/os/ubuntu.sh
  # shellcheck disable=SC1091
  . "$file"

  local req=(os_prepare_repos os_install_packages os_init_cluster os_get_paths os_restart)
  local missing=() fn
  for fn in "${req[@]}"; do declare -F "$fn" >/dev/null || missing+=("$fn"); done
  ((${#missing[@]}==0)) || { err "OS module '$OS_FAMILY' missing: ${missing[*]}"; exit 2; }
}

ensure_conf_dir_like_conf() {
  local conf_file="$1"
  local dropin_dir
  dropin_dir="$(dirname "$conf_file")/conf.d"
  local owner group
  if [[ -f "$conf_file" ]]; then
    owner=$(stat -c '%U' "$conf_file" 2>/dev/null || owner="")
    group=$(stat -c '%G' "$conf_file" 2>/dev/null || group="")
  fi
  if [[ ! -d "$dropin_dir" ]]; then
    if [[ -n "$owner" && -n "$group" ]]; then
      must_run install -d -o "$owner" -g "$group" -m 0700 "$dropin_dir"
    else
      must_run install -d -m 0700 "$dropin_dir"
    fi
  fi
}

write_key_value_dropin() {
  local f="$1" key="$2" val="$3"
  touch "$f"
  if grep -E -q "^\s*${key}\s*=\s*" "$f"; then
    run sed -i -E "s|^\s*(${key})\s*=.*$|\1 = ${val}|" "$f"
  else
    run bash -c "printf '%s\\n' \"${key} = ${val}\" >> \"$f\""
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default config (can be overridden via flags or env file)
PG_VERSION=${PG_VERSION:-16}
REPO_KIND=${REPO_KIND:-pgdg}       # pgdg|os
PORT=${PORT:-5432}
LISTEN_ADDRESSES=${LISTEN_ADDRESSES:-localhost}
ALLOWED_CIDR=${ALLOWED_CIDR:-}
ALLOWED_CIDR_V6=${ALLOWED_CIDR_V6:-}
DATA_DIR=${DATA_DIR:-auto}
ENABLE_TLS=${ENABLE_TLS:-false}
CREATE_DB=${CREATE_DB:-}
CREATE_USER=${CREATE_USER:-}
CREATE_PASSWORD=${CREATE_PASSWORD:-}
ALLOW_NETWORK=${ALLOW_NETWORK:-false}
PROFILE=${PROFILE:-}
ENV_FILE=${ENV_FILE:-}
DRY_RUN=${DRY_RUN:-false}
INIT_PG_STAT_STATEMENTS=${INIT_PG_STAT_STATEMENTS:-false}

# Local hardening flags 
SOCKET_ONLY=${SOCKET_ONLY:-}
UNIX_SOCKET_GROUP=${UNIX_SOCKET_GROUP:-pgclients}
UNIX_SOCKET_PERMISSIONS=${UNIX_SOCKET_PERMISSIONS:-0770}
UNIX_SOCKET_DIR=${UNIX_SOCKET_DIR:-}
LOCAL_PEER_MAP=${LOCAL_PEER_MAP:-localmap}
ADMIN_GROUP_ROLE=${ADMIN_GROUP_ROLE:-dba_group}
ADMIN_DBROLE=${ADMIN_DBROLE:-}
DISABLE_POSTGRES_LOGIN=${DISABLE_POSTGRES_LOGIN:-false}
declare -a LOCAL_MAP_ENTRIES

usage() {
  cat <<USAGE
Postgres Provisioner (PG16)
Usage: $0 \
  [--repo pgdg|os] [--port N] [--listen-addresses VAL] [--allowed-cidr CIDR] [--allowed-cidr-v6 CIDR6] \\
  [--data-dir PATH|auto] [--enable-tls] [--init-pg-stat-statements] \\
  [--create-db NAME] [--create-user NAME] [--create-password SECRET] [--allow-network] [--profile NAME] [--env-file FILE] [--dry-run] \\
  [--socket-only] [--unix-socket-group NAME] [--unix-socket-permissions MODE] [--unix-socket-dir PATH] \\
  [--local-peer-map NAME] [--local-map-entry OSUSER:DBROLE]... [--admin-group-role NAME] [--admin-dbrole NAME] [--disable-postgres-login]

Examples:
  sudo $0 --repo pgdg --listen-addresses '*' --allowed-cidr 10.0.0.0/8 --allow-network
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pg-version) PG_VERSION="$2"; shift 2;;
      --repo) REPO_KIND="$2"; shift 2;;
      --port) PORT="$2"; shift 2;;
      --listen-addresses) LISTEN_ADDRESSES="$2"; shift 2;;
      --allowed-cidr) ALLOWED_CIDR="$2"; shift 2;;
      --allowed-cidr-v6) ALLOWED_CIDR_V6="$2"; shift 2;;
      --data-dir) DATA_DIR="$2"; shift 2;;
      --enable-tls) ENABLE_TLS=true; shift 1;;
      --init-pg-stat-statements) INIT_PG_STAT_STATEMENTS=true; shift 1;;
      --create-db) CREATE_DB="$2"; shift 2;;
      --create-user) CREATE_USER="$2"; shift 2;;
      --create-password) CREATE_PASSWORD="$2"; shift 2;;
      --allow-network) ALLOW_NETWORK=true; shift 1;;
      --profile) PROFILE="$2"; shift 2;;
      --env-file) ENV_FILE="$2"; shift 2;;
      --socket-only) SOCKET_ONLY=true; shift 1;;
      --unix-socket-group) UNIX_SOCKET_GROUP="$2"; shift 2;;
      --unix-socket-permissions) UNIX_SOCKET_PERMISSIONS="$2"; shift 2;;
      --unix-socket-dir) UNIX_SOCKET_DIR="$2"; shift 2;;
      --local-peer-map) LOCAL_PEER_MAP="$2"; shift 2;;
      --local-map-entry) LOCAL_MAP_ENTRIES+=("$2"); shift 2;;
      --admin-group-role) ADMIN_GROUP_ROLE="$2"; shift 2;;
      --admin-dbrole) ADMIN_DBROLE="$2"; shift 2;;
      --disable-postgres-login) DISABLE_POSTGRES_LOGIN=true; shift 1;;
      --dry-run) DRY_RUN=true; shift 1;;
      -h|--help) usage; exit 0;;
      *) err "Unknown argument: $1"; usage; exit 2;;
    esac
  done
}

load_env_file() {
  if [[ -n "${ENV_FILE}" && -r "${ENV_FILE}" ]]; then
    log "Loading env file: ${ENV_FILE}"
    set -a; # export
    # shellcheck disable=SC1090
    . "${ENV_FILE}"; set +a
  fi
}

assert_psql_major_matches() {
  if ! command -v psql >/dev/null 2>&1; then
    err "psql not found after installation; expected PostgreSQL ${PG_VERSION} client"
    exit 2
  fi
  local ver
  ver=$(psql --version | awk '{print $3}' 2>/dev/null)
  if [[ -z "$ver" || "${ver%%.*}" != "${PG_VERSION}" ]]; then
    err "Expected PostgreSQL client ${PG_VERSION}.x, found: ${ver:-unknown}"
    exit 2
  fi
}

apply_dropin_config() {
  # Strict: fail if we cannot write conf.d or the drop-in
  local conf_file="$1" data_dir="$2" dropin_dir dropin
  dropin_dir="$(dirname "$conf_file")/conf.d"
  dropin="${dropin_dir}/99-pgprovision.conf"

  ensure_conf_dir_like_conf "$conf_file"
  ensure_line "$conf_file" "include_dir = 'conf.d'"

  write_key_value_dropin "$dropin" port "$PORT"
  write_key_value_dropin "$dropin" listen_addresses "'${LISTEN_ADDRESSES}'"
  write_key_value_dropin "$dropin" password_encryption "scram-sha-256"
  write_key_value_dropin "$dropin" shared_preload_libraries "'pg_stat_statements'"
  write_key_value_dropin "$dropin" logging_collector on
  write_key_value_dropin "$dropin" log_min_duration_statement "250ms"
  write_key_value_dropin "$dropin" log_connections on
  write_key_value_dropin "$dropin" log_disconnections on
  write_key_value_dropin "$dropin" log_line_prefix "'%m [%p] user=%u db=%d app=%a client=%h '"

  # Socket gating
  write_key_value_dropin "$dropin" unix_socket_group "'${UNIX_SOCKET_GROUP}'"
  write_key_value_dropin "$dropin" unix_socket_permissions "${UNIX_SOCKET_PERMISSIONS}"
  if [[ -n "${UNIX_SOCKET_DIR}" ]]; then
    write_key_value_dropin "$dropin" unix_socket_directories "'${UNIX_SOCKET_DIR}'"
  fi

  if [[ ${#PROFILE_OVERRIDES[@]} -gt 0 ]]; then
    for kv in "${PROFILE_OVERRIDES[@]}"; do
      local k="${kv%%=*}" v="${kv#*=}"
      write_key_value_dropin "$dropin" "$k" "$v"
    done
  fi

  if [[ "$ENABLE_TLS" == "true" ]]; then
    write_key_value_dropin "$dropin" ssl on
    write_key_value_dropin "$dropin" ssl_min_protocol_version "TLSv1.2"
    write_key_value_dropin "$dropin" ssl_prefer_server_ciphers on
  fi

  # Tighten permissions on drop-in to match/confine to base conf owner and 0600 mode
  must_run chown --reference "$conf_file" "$dropin"
  must_run chmod 0600 "$dropin"
}

replace_managed_block_top() {
  local file="$1"; shift
  local begin_marker="$1"; shift
  local end_marker="$1"; shift
  local content="$1"
  local tmp new mode owner group
  tmp="$(mktemp)"; new="$(mktemp)"
  if [[ -f "$file" ]]; then
    mode=$(must_stat -c '%a' "$file")
    owner=$(must_stat -c '%U' "$file")
    group=$(must_stat -c '%G' "$file")
    awk -v b="$begin_marker" -v e="$end_marker" '
      BEGIN {ib=0}
      $0==b {ib=1; next}
      ib==1 && $0==e {ib=0; next}
      ib==0 {print}
    ' "$file" >"$tmp"
  else
    : >"$tmp"
  fi
  {
    printf '%s\n' "$content"
    cat "$tmp"
  } >"$new"
  must_run mv -f "$new" "$file"
  if [[ -n "$owner$group" ]]; then must_run chown "$owner:$group" "$file"; fi
  if [[ -n "$mode" ]]; then must_run chmod "$mode" "$file"; fi
  must_rm -f "$tmp"
}

write_pg_ident_map() {
  local ident_file="$1"
  local begin="# pgprovision:pg_ident begin (managed)"
  local end="# pgprovision:pg_ident end"
  local buf
  buf=$(printf '%s\n' "$begin" "# MAPNAME SYSTEM-USER DB-ROLE")
  local entry osuser dbrole
  for entry in "${LOCAL_MAP_ENTRIES[@]:-}"; do
    [[ -z "$entry" ]] && continue
    osuser="${entry%%:*}"; dbrole="${entry#*:}"
    buf=$(printf '%s\n%s %s %s' "$buf" "$LOCAL_PEER_MAP" "$osuser" "$dbrole")
  done
  buf=$(printf '%s\n%s\n' "$buf" "$end")
  replace_managed_block_top "$ident_file" "$begin" "$end" "$buf"
}

ensure_socket_group_and_members() {
  local group="$1"; shift
  # Ensure group exists
  if ! getent group "$group" >/dev/null; then
    must_run groupadd -f "$group"
  fi
  # Ensure postgres belongs to the socket group
  if id -u postgres >/dev/null 2>&1; then
    must_run usermod -aG "$group" postgres
  fi
  # Add mapped OS users to the socket group
  local entry osuser
  for entry in "${LOCAL_MAP_ENTRIES[@]:-}"; do
    osuser="${entry%%:*}"
    if id -u "$osuser" >/dev/null 2>&1; then
      must_run usermod -aG "$group" "$osuser"
    fi
  done
}

create_db_and_user() {
  [[ -z "$CREATE_DB$CREATE_USER" ]] && return 0
  local psql=(sudo -u postgres psql -v ON_ERROR_STOP=1 -XAt)
  if [[ -n "$CREATE_USER" ]]; then
    # Escape identifier (double quotes) and literal (single quotes)
    local _user_ident; _user_ident=$(printf '%s' "$CREATE_USER" | sed 's/\"/\"\"/g')
    local _user_lit;   _user_lit=$(printf '%s' "$CREATE_USER" | sed "s/'/''/g")
    local _pass_lit;   _pass_lit=$(printf '%s' "${CREATE_PASSWORD}" | sed "s/'/''/g")
    "${psql[@]}" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${_user_lit}') THEN CREATE ROLE \"${_user_ident}\" LOGIN PASSWORD '${_pass_lit}'; END IF; END \$\$;" || warn "role create failed"
  fi
  if [[ -n "$CREATE_DB" ]]; then
    local _db_ident;   _db_ident=$(printf '%s' "$CREATE_DB" | sed 's/\"/\"\"/g')
    local _db_lit;     _db_lit=$(printf '%s' "$CREATE_DB" | sed "s/'/''/g")
    local _owner;      _owner="${CREATE_USER:-postgres}"
    local _owner_ident; _owner_ident=$(printf '%s' "${_owner}" | sed 's/\"/\"\"/g')
    "${psql[@]}" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_database WHERE datname='${_db_lit}') THEN CREATE DATABASE \"${_db_ident}\" OWNER \"${_owner_ident}\"; END IF; END \$\$;" || warn "db create failed"
  fi
}

conditionally_init_pg_stat_statements() {
  [[ "$INIT_PG_STAT_STATEMENTS" != "true" ]] && return 0
  # Create the extension if not present (requires shared_preload_libraries configured and server restarted)
  local cmd=(sudo -u postgres psql -v ON_ERROR_STOP=1 -XAt)
  if command -v psql >/dev/null 2>&1 || sudo -u postgres psql -V >/dev/null 2>&1; then
    "${cmd[@]}" -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;" || warn "pg_stat_statements creation failed"
  else
    warn "psql not available; cannot create pg_stat_statements"
  fi
}

write_stamp() {
  local data_dir="$1"; ensure_dir "$data_dir"
  local stamp="${data_dir}/.pgprovision_provisioned.json"
  run bash -c "cat > '${stamp}' <<JSON
{
  \"port\": ${PORT},
  \"listen_addresses\": \"${LISTEN_ADDRESSES}\",
  \"repo\": \"${REPO_KIND}\",
  \"allow_network\": ${ALLOW_NETWORK},
  \"enable_tls\": ${ENABLE_TLS},
  \"profile\": \"${PROFILE}\"
}
JSON"
  if [[ -n "${CONF_FILE:-}" && -f "$CONF_FILE" ]]; then
    run chown --reference "$CONF_FILE" "$stamp" || true
    run chmod 0600 "$stamp" || true
  fi
}

setup_role_mappings_and_admin() {
  # Create DB roles for mappings and optional admin group/login.
  local psql=(sudo -u postgres psql -v ON_ERROR_STOP=1 -XAt)
  local entry dbrole dbrole_lit dbrole_ident
  for entry in "${LOCAL_MAP_ENTRIES[@]:-}"; do
    dbrole="${entry#*:}"
    [[ -z "$dbrole" ]] && continue
    dbrole_ident=$(printf '%s' "$dbrole" | sed 's/\"/\"\"/g')
    dbrole_lit=$(printf "%s" "$dbrole" | sed "s/'/''/g")
    "${psql[@]}" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${dbrole_lit}') THEN CREATE ROLE \"${dbrole_ident}\" LOGIN; END IF; END \$\$;" || warn "create role ${dbrole} failed"
  done
  if [[ -n "${ADMIN_GROUP_ROLE}" ]]; then
    local g_ident g_lit
    g_ident=$(printf '%s' "$ADMIN_GROUP_ROLE" | sed 's/\"/\"\"/g')
    g_lit=$(printf '%s' "$ADMIN_GROUP_ROLE" | sed "s/'/''/g")
    "${psql[@]}" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${g_lit}') THEN CREATE ROLE \"${g_ident}\" SUPERUSER NOLOGIN; END IF; END \$\$;" || warn "create group ${ADMIN_GROUP_ROLE} failed"
    if [[ -n "${ADMIN_DBROLE}" ]]; then
      local a_ident a_lit
      a_ident=$(printf '%s' "$ADMIN_DBROLE" | sed 's/\"/\"\"/g')
      a_lit=$(printf '%s' "$ADMIN_DBROLE" | sed "s/'/''/g")
      "${psql[@]}" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${a_lit}') THEN CREATE ROLE \"${a_ident}\" LOGIN NOINHERIT; END IF; END \$\$;" || warn "create admin ${ADMIN_DBROLE} failed"
      "${psql[@]}" -c "GRANT \"${g_ident}\" TO \"${a_ident}\";" || warn "grant ${ADMIN_GROUP_ROLE} to ${ADMIN_DBROLE} failed"
    fi
  fi
  if [[ "${DISABLE_POSTGRES_LOGIN}" == "true" ]]; then
    warn "ALTER ROLE postgres NOLOGIN requested; ensure you have verified admin login + SET ROLE path before enabling this."
    "${psql[@]}" -c "ALTER ROLE postgres NOLOGIN;" || warn "failed to set postgres NOLOGIN"
  fi
}

main() {
  require_root_or_sudo
  parse_args "$@"
  load_env_file
  os_detect
  load_os_module

  log "Provisioning PostgreSQL ${PG_VERSION} on ${OS_FAMILY} (repo=${REPO_KIND})"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "Dry-run: would prepare repos, install packages, and configure"
    exit 0
  fi

  os_prepare_repos "$REPO_KIND"
  os_install_packages
  assert_psql_major_matches
  os_init_cluster "$DATA_DIR"

  # Resolve paths
  eval "$(os_get_paths)"  # sets CONF_FILE, HBA_FILE, IDENT_FILE, DATA_DIR, SERVICE
  log "CONF=${CONF_FILE} HBA=${HBA_FILE} IDENT=${IDENT_FILE:-unknown} DATA=${DATA_DIR} SERVICE=${SERVICE}"

  load_profile_overrides
  apply_dropin_config "$CONF_FILE" "$DATA_DIR"
  ensure_socket_group_and_members "$UNIX_SOCKET_GROUP"
  apply_hba_policy "$HBA_FILE"

  if [[ -n "${IDENT_FILE:-}" ]]; then
    write_pg_ident_map "$IDENT_FILE"
    # Ensure pg_ident.conf attributes are tight even if created fresh
    run chown --reference "$CONF_FILE" "$IDENT_FILE" || true
    run chmod 0600 "$IDENT_FILE" || true
  fi

  # If TLS is requested, ensure cert/key exist before restart
  if [[ "$ENABLE_TLS" == "true" ]]; then
    if [[ ! -r "${DATA_DIR}/server.crt" || ! -r "${DATA_DIR}/server.key" ]]; then
      err "TLS enabled but ${DATA_DIR}/server.crt or ${DATA_DIR}/server.key missing"; exit 1
    fi
  fi

  os_restart "$SERVICE"
  conditionally_init_pg_stat_statements
  setup_role_mappings_and_admin || true
  create_db_and_user || true
  write_stamp "$DATA_DIR"

  log "PostgreSQL provisioning completed."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
