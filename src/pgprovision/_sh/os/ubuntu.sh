#!/usr/bin/env bash
# Ubuntu 22.04/24.04 + PGDG helpers

: "${PG_VERSION:=16}"

_apt_update_once_done="false"
_cnf_hook="/etc/apt/apt.conf.d/50command-not-found"
_cnf_stash="/run/pgprovision-apt-stash"

_disable_cnf_hook() {
	if [[ -f "${_cnf_hook}" ]]; then
		run install -d -m 0755 "${_cnf_stash}"
		run mv -f "${_cnf_hook}" "${_cnf_stash}/"
		echo "+ disabled command-not-found APT hook"
	fi
}

_restore_cnf_hook() {
	if [[ -f "${_cnf_stash}/50command-not-found" ]]; then
		run mv -f "${_cnf_stash}/50command-not-found" "${_cnf_hook}"
		rmdir "${_cnf_stash}" 2>/dev/null || true
		echo "+ restored command-not-found APT hook"
	fi
}

_apt_update_once() {
	if [[ "${_apt_update_once_done}" != "true" ]]; then
		# Always restore the 'command-not-found' hook even if apt-get fails midway.
		# Using a RETURN trap ensures cleanup on both success and failure.
		trap '_restore_cnf_hook || true' RETURN
		# Disable problematic APT post-invoke hook that may import apt_pkg with a mismatched python3.
		_disable_cnf_hook || true
		# Try update with hook suppressed, then fallback to normal update.
		if ! run "${SUDO[@]}" apt-get -o APT::Update::Post-Invoke-Success= -y update; then
			run "${SUDO[@]}" apt-get update
		fi
		_apt_update_once_done="true"
		# Optional: stop triggering the RETURN trap for all later function returns
		trap - RETURN
	fi
}

os_prepare_repos() {
	local repo_kind="${1:-pgdg}"
	if [[ "$repo_kind" != "pgdg" ]]; then
		warn "Ubuntu path supports only --repo=pgdg; ignoring --repo=${repo_kind}."
	fi

	_apt_update_once
	run "${SUDO[@]}" apt-get install -y curl ca-certificates gnupg lsb-release
	run "${SUDO[@]}" install -d -m 0755 -- /etc/apt/keyrings
	run bash -c "set -o pipefail; curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | ${SUDO[*]} gpg --yes --batch --dearmor -o /etc/apt/keyrings/postgresql.gpg"
	run "${SUDO[@]}" chmod 0644 /etc/apt/keyrings/postgresql.gpg
	local codename
	codename=$(lsb_release -cs)
	run bash -c "echo 'deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main' \
		| ${SUDO[*]} tee /etc/apt/sources.list.d/pgdg.list >/dev/null"
	# Ensure PGDG is visible for the subsequent install step
	run "${SUDO[@]}" apt-get update
}

os_install_packages() {
	_apt_update_once
	run "${SUDO[@]}" apt-get install -y "postgresql-${PG_VERSION}" "postgresql-client-${PG_VERSION}" postgresql-contrib
}

os_init_cluster() {
	local data_dir="${1:-auto}"
	# Ubuntu auto-creates the default cluster when postgresql-${PG_VERSION} is installed via PGDG.
	# A custom data dir requires cluster tooling.

	if [[ "$data_dir" != "auto" && -n "$data_dir" ]]; then
		# Ensure the postgresql-common tools exist if we plan to move/create clusters.
		if ! command -v pg_dropcluster >/dev/null 2>&1 || ! command -v pg_createcluster >/dev/null 2>&1; then
			err "pg_dropcluster/pg_createcluster not available; cannot relocate data dir to ${data_dir}"
			exit 2
		fi

		# Detect current cluster data dir (if the cluster exists at all).
		local cur=""
		if command -v pg_lsclusters >/dev/null 2>&1; then
			cur=$(pg_lsclusters --no-header | awk '$1=="'"${PG_VERSION}"'" && $2=="main"{print $6; exit}')
		fi

		# --- Early return: already at desired data_dir
		if [[ -n "$cur" && "$cur" == "$data_dir" ]]; then
			# Nothing to relocate; just ensure the service is enabled and running.
			run "${SUDO[@]}" systemctl enable --now "postgresql@${PG_VERSION}-main"
			return 0
		fi

		# We need to (re)create the cluster pointing at the requested data_dir.
		# Stop if active, then drop the existing 'main' (if present).
		if systemctl is-active --quiet "postgresql@${PG_VERSION}-main"; then
			run "${SUDO[@]}" systemctl stop "postgresql@${PG_VERSION}-main"
		fi
		# Drop only if the cluster currently exists; pg_dropcluster errors if not present.
		if [[ -n "$cur" ]]; then
			run "${SUDO[@]}" pg_dropcluster --stop "${PG_VERSION}" main
		fi

		# Prepare the target dir and AppArmor permissions (idempotent).
		run "${SUDO[@]}" install -d -m 0700 -- "$data_dir"
		ubuntu_apparmor_allow_datadir "$data_dir" || true

		# Create a fresh 'main' at the requested location.
		run "${SUDO[@]}" pg_createcluster "${PG_VERSION}" main -d "$data_dir"
	fi

	# Default path or after relocation: ensure service is enabled & started.
	run "${SUDO[@]}" systemctl enable --now "postgresql@${PG_VERSION}-main"
}

os_get_paths() {
	local conf="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
	local hba="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"
	local ident="/etc/postgresql/${PG_VERSION}/main/pg_ident.conf"
	local svc="postgresql@${PG_VERSION}-main"
	local datadir=""

	# Preferred: ask postgresql-common
	if command -v pg_lsclusters >/dev/null 2>&1; then
		datadir=$(pg_lsclusters --no-header | awk '$1=="'"${PG_VERSION}"'" && $2=="main"{print $6; exit}')
	fi

	if [[ -z "$datadir" && -r "$conf" ]]; then
		datadir=$(
			awk -F= '
        /^[[:space:]]*data_directory[[:space:]]*=/ {
          v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); gsub(/^'\''|'\''$/, "", v); gsub(/^"|"$/, "", v);
          print v; exit
        }' "$conf" 2>/dev/null || true
		)
	fi

	# Last resort: Debian default
	[[ -z "$datadir" ]] && datadir="/var/lib/postgresql/${PG_VERSION}/main"

	echo "CONF_FILE=$conf HBA_FILE=$hba IDENT_FILE=$ident DATA_DIR=$datadir SERVICE=$svc"
}

os_enable_and_start() {
	local svc="${1:-postgresql@${PG_VERSION}-main}"
	run "${SUDO[@]}" systemctl enable --now "$svc"
}

os_restart() {
	local svc="${1:-postgresql@${PG_VERSION}-main}"
	run "${SUDO[@]}" systemctl restart "$svc"
}

ubuntu_apparmor_allow_datadir() {
	local dir="$1"
	# Paths per Ubuntu packaging of PostgreSQL
	local profile="/etc/apparmor.d/usr.lib.postgresql.postgres"
	local local_override="/etc/apparmor.d/local/usr.lib.postgresql.postgres"
	run "${SUDO[@]}" install -d -m 0755 -- "$(dirname "$local_override")"
	local rule="  ${dir}/** rwk,"
	run bash -c "grep -Fqx -- \"$rule\" \"$local_override\" 2>/dev/null || printf '%s\n' \"$rule\" | ${SUDO[*]} tee -a \"$local_override\" >/dev/null"
	if command -v apparmor_parser >/dev/null 2>&1 && [[ -f "$profile" ]]; then
		run "${SUDO[@]}" apparmor_parser -r "$profile" || warn "apparmor_parser reload failed"
	else
		# Fallback: try service reload
		if systemctl list-units --type=service | grep -q apparmor; then
			run "${SUDO[@]}" systemctl reload apparmor || true
		fi
	fi
}
