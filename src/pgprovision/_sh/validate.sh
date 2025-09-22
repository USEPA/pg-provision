#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Minimal inlined helpers
run() {
	echo "+ $*"
	"$@"
}
os_detect() {
	if [[ -r /etc/os-release ]]; then
		. /etc/os-release
		case "${ID:-}" in
		rhel | rocky | almalinux | centos) OS_FAMILY="rhel" ;;
		ubuntu) OS_FAMILY="ubuntu" ;;
		*)
			echo "Unsupported OS ID: ${ID:-unknown}" 1>&2
			exit 2
			;;
		esac
		OS_VERSION_ID="${VERSION_ID:-}"
		OS_CODENAME="${UBUNTU_CODENAME:-}"
	else
		echo "/etc/os-release not found; cannot detect OS" 1>&2
		exit 2
	fi
}

os_detect

# Load OS paths
case "$OS_FAMILY" in
rhel) . "${SCRIPT_DIR}/os/rhel.sh" ;;
ubuntu) . "${SCRIPT_DIR}/os/ubuntu.sh" ;;
esac

# Resolve paths; fail fast on errors
if ! declare -F os_get_paths >/dev/null 2>&1; then
	echo "[validate][error] os_get_paths not available" >&2
	exit 2
fi
paths="$(os_get_paths)" || {
	echo "[validate][error] os_get_paths failed" >&2
	exit 2
}
eval "$paths"

if ! command -v psql >/dev/null 2>&1; then
	echo "[validate][error] psql not installed" >&2
	exit 127
fi
psql_ver=$(psql --version)
service_status="unknown"
if [[ -n "${SERVICE:-}" ]]; then
	if systemctl is-active --quiet "$SERVICE"; then service_status="active"; else service_status="inactive"; fi
fi

# Extract SHOW config_file/hba_file if possible
show_conf=""
show_hba=""
pg_ready="false"
if command -v pg_isready >/dev/null 2>&1; then
	if pg_isready >/dev/null 2>&1; then pg_ready="true"; fi
fi
ssl=""
ssl_min=""
ssl_pref=""
if command -v psql >/dev/null 2>&1; then
	show_conf=$(psql -XAtqc "SHOW config_file;" 2>/dev/null || echo "")
	show_hba=$(psql -XAtqc "SHOW hba_file;" 2>/dev/null || echo "")
	ssl=$(psql -XAtqc "SHOW ssl;" 2>/dev/null || echo "")
	ssl_min=$(psql -XAtqc "SHOW ssl_min_protocol_version;" 2>/dev/null || echo "")
	ssl_pref=$(psql -XAtqc "SHOW ssl_prefer_server_ciphers;" 2>/dev/null || echo "")
fi

# Lightweight localhost HBA checks (report-only; non-fatal)
hba_local_peer_present=false
hba_local_peer_dupes=0
hba_loopback_v4_present=false
hba_loopback_v4_dupes=0
hba_loopback_v6_present=false
hba_loopback_v6_dupes=0
if [[ -n "${HBA_FILE:-}" && -r "${HBA_FILE}" ]]; then
	# Count exact matches to detect duplicates
	hba_local_peer_dupes=$(grep -E -c "^\s*local\s+all\s+all\s+peer\s*$" "$HBA_FILE" || echo 0)
	hba_loopback_v4_dupes=$(grep -E -c "^\s*host\s+all\s+all\s+127\.0\.0\.1/32\s+scram-sha-256\s*$" "$HBA_FILE" || echo 0)
	hba_loopback_v6_dupes=$(grep -E -c "^\s*host\s+all\s+all\s+::1/128\s+scram-sha-256\s*$" "$HBA_FILE" || echo 0)
	[[ "$hba_local_peer_dupes" -ge 1 ]] && hba_local_peer_present=true
	[[ "$hba_loopback_v4_dupes" -ge 1 ]] && hba_loopback_v4_present=true
	[[ "$hba_loopback_v6_dupes" -ge 1 ]] && hba_loopback_v6_present=true
fi

# Report extension presence (non-fatal)
pgss_installed=false
if command -v psql >/dev/null 2>&1; then
	if psql -XAtqc "SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements' LIMIT 1;" >/dev/null 2>&1; then
		pgss_installed=true
	fi
fi

cat <<JSON
{
  "os": {"family": "${OS_FAMILY}", "version_id": "${OS_VERSION_ID}", "codename": "${OS_CODENAME}"},
  "postgres": {
    "psql_version": "${psql_ver}",
    "service": "${SERVICE:-}",
    "service_status": "${service_status}",
    "data_dir": "${DATA_DIR:-}",
    "config_file": "${CONF_FILE:-}",
    "hba_file": "${HBA_FILE:-}",
    "show_config_file": "${show_conf}",
  "show_hba_file": "${show_hba}",
    "ssl": "${ssl}",
    "ssl_min_protocol_version": "${ssl_min}",
    "ssl_prefer_server_ciphers": "${ssl_pref}",
    "pg_isready": ${pg_ready}
  },
  "checks": {
    "hba": {
      "local_peer": {"present": ${hba_local_peer_present}, "count": ${hba_local_peer_dupes}},
      "loopback_v4": {"present": ${hba_loopback_v4_present}, "count": ${hba_loopback_v4_dupes}},
      "loopback_v6": {"present": ${hba_loopback_v6_present}, "count": ${hba_loopback_v6_dupes}}
    },
    "pg_stat_statements_installed": ${pgss_installed}
  }
}
JSON
