#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Minimal shared helpers (inlined; previously from lib/common.sh)
_c_green="\033[0;32m"; _c_yellow="\033[0;33m"; _c_red="\033[0;31m"; _c_reset="\033[0m" || true
log() { echo -e "${_c_green}[airules:pg]${_c_reset} $*"; }
warn() { echo -e "${_c_yellow}[airules:pg][warn]${_c_reset} $*" 1>&2; }
err()  { echo -e "${_c_red}[airules:pg][error]${_c_reset} $*" 1>&2; }
run() { echo "+ $*"; "$@"; }
require_root_or_sudo() {
  if [[ $(id -u) -eq 0 ]]; then return 0; fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then return 0; fi
  err "This script needs root or passwordless sudo (sudo -n)."
  exit 1
}
os_detect() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
      rhel|rocky|almalinux|centos) OS_FAMILY="rhel" ;;
      ubuntu) OS_FAMILY="ubuntu" ;;
      *) err "Unsupported OS ID: ${ID:-unknown}"; exit 2 ;;
    esac
    OS_VERSION_ID="${VERSION_ID:-}"; OS_CODENAME="${UBUNTU_CODENAME:-}"
  else
    err "/etc/os-release not found; cannot detect OS"; exit 2
  fi
}
ensure_hba_rule() {
  local f="$1"; shift; local rule="$*"; touch "$f"
  if ! grep -Fqx -- "$rule" "$f" 2>/dev/null; then
    echo "$rule" >>"$f"
  fi
}

# Strict file ops used for conf.d drop-in
ensure_dir() {
  local d="$1"
  # If directory already exists, do NOT modify its permissions (preserve e.g., PGDATA 0700/0750)
  if [[ -d "$d" ]]; then
    echo "+ dir exists: $d"
    return 0
  fi
  # Try as current user first; fall back to passwordless sudo if needed
  if install -d -m 0755 "$d" 2>/dev/null; then
    echo "+ install -d -m 0755 $d"
    return 0
  fi
  if [[ $(id -u) -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    run sudo -n install -d -m 0755 "$d"
  else
    err "Cannot create directory $d (no permission or sudo)"; exit 1
  fi
}
ensure_conf_dir_like_conf() {
  local conf_file="$1"
  local dropin_dir
  dropin_dir="$(dirname "$conf_file")/conf.d"
  local owner group
  if [[ -f "$conf_file" ]]; then
    owner=$(stat -c '%U' "$conf_file" 2>/dev/null || true)
    group=$(stat -c '%G' "$conf_file" 2>/dev/null || true)
  fi
  if [[ ! -d "$dropin_dir" ]]; then
    if [[ -n "$owner$group" ]]; then
      run install -d -o "$owner" -g "$group" -m 0700 "$dropin_dir"
    else
      run install -d -m 0700 "$dropin_dir"
    fi
  fi
}
ensure_line() {
  local f="$1"; shift; local line="$*"
  # Append only if the exact line is not already present (idempotent)
  if ! grep -Fqx -- "$line" "$f" 2>/dev/null; then
    run bash -c "printf '%s\\n' \"$line\" >> \"$f\""
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

# Local hardening flags (RHEL socket-only Option A by default)
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
airules Postgres Provisioner (PG16)
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

apply_profile_overrides() {
  case "${PROFILE}" in
    xl-32c-256g)
      PROFILE_OVERRIDES=(
        "shared_buffers=64GB"
        "effective_cache_size=192GB"
        "work_mem=32MB"
        "maintenance_work_mem=2GB"
        "autovacuum_work_mem=2GB"
        "wal_buffers=16MB"
        "max_wal_size=32GB"
        "min_wal_size=4GB"
        "checkpoint_timeout=15min"
        "checkpoint_completion_target=0.9"
        "effective_io_concurrency=256"
        "random_page_cost=1.1"
        "seq_page_cost=1.0"
        "default_statistics_target=250"
        "track_io_timing=on"
        "max_worker_processes=32"
        "max_parallel_workers=32"
        "max_parallel_workers_per_gather=8"
        "max_parallel_maintenance_workers=4"
        "autovacuum_max_workers=10"
        "autovacuum_naptime=10s"
        "autovacuum_vacuum_scale_factor=0.10"
        "autovacuum_analyze_scale_factor=0.05"
        "autovacuum_vacuum_cost_limit=2000"
        "autovacuum_vacuum_cost_delay=2ms"
        "idle_in_transaction_session_timeout=5min"
        "log_checkpoints=on"
        "log_autovacuum_min_duration=5s"
      )
      ;;
    "" ) :;;
    *)
      warn "Unknown profile: ${PROFILE}; ignoring";;
  esac
}

assert_psql_is_16() {
  # Ensure installed client is version 16.x; fail otherwise.
  if ! command -v psql >/dev/null 2>&1; then
    err "psql not found after installation; expected PostgreSQL 16 client"
    exit 2
  fi
  local ver
  ver=$(psql --version | awk '{print $3}' 2>/dev/null || true)
  # Accept forms like 16, 16.0, 16.3
  if [[ -z "$ver" || "${ver%%.*}" != "16" ]]; then
    err "Expected PostgreSQL client 16.x, found: ${ver:-unknown}"
    exit 2
  fi
}

apply_dropin_config() {
  # Strict: fail if we cannot write conf.d or the drop-in
  local conf_file="$1" data_dir="$2" dropin_dir dropin
  dropin_dir="$(dirname "$conf_file")/conf.d"
  dropin="${dropin_dir}/99-airules.conf"

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

  if [[ -n "${PROFILE:-}" ]]; then
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
  run chown --reference "$conf_file" "$dropin" || true
  run chmod 0600 "$dropin" || true
}

apply_hba_rules() {
  local hba_file="$1"
  # Default local rules; idempotent append of exact lines
  ensure_hba_rule "$hba_file" "local   all             all                                     peer"
  ensure_hba_rule "$hba_file" "host    all             all             127.0.0.1/32            scram-sha-256"
  ensure_hba_rule "$hba_file" "host    all             all             ::1/128                 scram-sha-256"
  if [[ -n "${ALLOWED_CIDR:-}" ]]; then
    local proto="host"
    [[ "${ENABLE_TLS:-false}" == "true" ]] && proto="hostssl"
    ensure_hba_rule "$hba_file" "$proto    all    all    ${ALLOWED_CIDR}    scram-sha-256"
  fi
  if [[ -n "${ALLOWED_CIDR_V6:-}" ]]; then
    local proto="host"
    [[ "${ENABLE_TLS:-false}" == "true" ]] && proto="hostssl"
    ensure_hba_rule "$hba_file" "$proto    all    all    ${ALLOWED_CIDR_V6}    scram-sha-256"
  fi
}

replace_managed_block_top() {
  local file="$1"; shift
  local begin_marker="$1"; shift
  local end_marker="$1"; shift
  local content="$1"
  local tmp new mode owner group
  tmp="$(mktemp)"; new="$(mktemp)"
  if [[ -f "$file" ]]; then
    mode=$(stat -c '%a' "$file" 2>/dev/null || true)
    owner=$(stat -c '%U' "$file" 2>/dev/null || true)
    group=$(stat -c '%G' "$file" 2>/dev/null || true)
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
  run mv -f "$new" "$file"
  if [[ -n "$owner$group" ]]; then run chown "$owner:$group" "$file" || true; fi
  if [[ -n "$mode" ]]; then run chmod "$mode" "$file" || true; fi
  rm -f "$tmp" || true
}

apply_hardened_hba() {
  local hba_file="$1"
  local begin="# airules:hba begin (managed)"
  local end="# airules:hba end"
  local header
  header=$(cat <<HBA
${begin}
# Enforce peer+map for local connections; keep postgres peer for provisioning
local   all   postgres                      peer
local   all   all                           peer map=${LOCAL_PEER_MAP}
local   all   all                           reject
# Explicit loopback TCP reject for defense-in-depth
host    all   all   127.0.0.1/32            reject
host    all   all   ::1/128                 reject
${end}
HBA
)
  replace_managed_block_top "$hba_file" "$begin" "$end" "$header"
}

write_pg_ident_map() {
  local ident_file="$1"
  local begin="# airules:pg_ident begin (managed)"
  local end="# airules:pg_ident end"
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
    run groupadd -f "$group"
  fi
  # Ensure postgres belongs to the socket group
  if id -u postgres >/dev/null 2>&1; then
    run usermod -aG "$group" postgres || true
  fi
  # Add mapped OS users to the socket group
  local entry osuser
  for entry in "${LOCAL_MAP_ENTRIES[@]:-}"; do
    osuser="${entry%%:*}"
    if id -u "$osuser" >/dev/null 2>&1; then
      run usermod -aG "$group" "$osuser" || true
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
  local stamp="${data_dir}/.airules_provisioned.json"
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
  apply_profile_overrides
  os_detect

  # Source OS module
  case "$OS_FAMILY" in
    rhel) . "${SCRIPT_DIR}/../../environments/rhel/provision/postgres/rhel.sh" ;;
    ubuntu) . "${SCRIPT_DIR}/../../environments/ubuntu/provision/postgres/ubuntu.sh" ;;
    *) err "Unsupported OS family: $OS_FAMILY"; exit 2;;
  esac

  # Hardened RHEL: force local-only bindings and ignore network flags
  if [[ "$OS_FAMILY" == "rhel" ]]; then
    # “Default to socket‑only on RHEL.
    # To enable TCP, set SOCKET_ONLY=false (via env or a future flag).
    # --listen-addresses/--allow-network are ignored while socket‑only is true.”
    if [[ -z "${SOCKET_ONLY}" ]]; then SOCKET_ONLY=true; fi
    if [[ "${SOCKET_ONLY}" == "true" ]]; then
      LISTEN_ADDRESSES=''
      ALLOWED_CIDR=""
      ALLOWED_CIDR_V6=""
      ALLOW_NETWORK=false
    fi
  fi

  log "Provisioning PostgreSQL 16 on ${OS_FAMILY} (repo=${REPO_KIND})"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "Dry-run: would prepare repos, install packages, and configure"
    exit 0
  fi

  os_prepare_repos "$REPO_KIND"
  os_install_packages
  assert_psql_is_16
  os_init_cluster "$DATA_DIR"

  # Resolve paths
  eval "$(os_get_paths)"  # sets CONF_FILE, HBA_FILE, IDENT_FILE, DATA_DIR, SERVICE
  log "CONF=${CONF_FILE} HBA=${HBA_FILE} IDENT=${IDENT_FILE:-unknown} DATA=${DATA_DIR} SERVICE=${SERVICE}"

  apply_dropin_config "$CONF_FILE" "$DATA_DIR"
  ensure_socket_group_and_members "$UNIX_SOCKET_GROUP"
  apply_hardened_hba "$HBA_FILE"
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
  conditionally_init_pg_stat_statements || true
  setup_role_mappings_and_admin || true
  #create_db_and_user || true
  write_stamp "$DATA_DIR"

  log "PostgreSQL provisioning completed."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
