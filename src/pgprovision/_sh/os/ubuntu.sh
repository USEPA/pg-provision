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
		# Disable problematic APT post-invoke hook that may import apt_pkg with a mismatched python3.
		_disable_cnf_hook || true
		# Try update with hook suppressed, then fallback to normal update.
		if ! run "${SUDO[@]}" apt-get -o APT::Update::Post-Invoke-Success= -y update; then
			run "${SUDO[@]}" apt-get update
		fi
		_restore_cnf_hook || true
		_apt_update_once_done="true"
	fi
}

os_prepare_repos() {
	local repo_kind="${1:-pgdg}"

	_apt_update_once
	run "${SUDO[@]}" apt-get install -y curl ca-certificates gnupg lsb-release
	run "${SUDO[@]}" install -d -m 0755 -- /etc/apt/keyrings
	run bash -c "curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
                 | ${SUDO[*]} gpg --yes --batch --dearmor -o /etc/apt/keyrings/postgresql.gpg"
	local codename
	codename=$(lsb_release -cs)
	run bash -c "echo 'deb [signed-by=/etc/apt/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main' \
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
	# Ubuntu auto-creates 16 cluster when postgresql-${PG_VERSION} is installed via PGDG.
	# Custom data dir requires cluster tooling; enforce availability and success.
	if [[ "$data_dir" != "auto" && -n "$data_dir" ]]; then
		if ! command -v pg_dropcluster >/dev/null 2>&1 || ! command -v pg_createcluster >/dev/null 2>&1; then
			err "pg_dropcluster/pg_createcluster not available; cannot relocate data dir to ${data_dir}"
			exit 2
		fi
		if systemctl is-active --quiet "postgresql@${PG_VERSION}-main"; then run "${SUDO[@]}" systemctl stop "postgresql@${PG_VERSION}-main"; fi
		run "${SUDO[@]}" pg_dropcluster --stop "${PG_VERSION}" main
		run "${SUDO[@]}" install -d -m 0700 -- "$data_dir"
		ubuntu_apparmor_allow_datadir "$data_dir" || true # defensive: non-fatal on systems without AppArmor
		run "${SUDO[@]}" pg_createcluster "${PG_VERSION}" main -d "$data_dir"
	fi
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
	run bash -c "printf '%s\n' \"$rule\" | ${SUDO[*]} tee -a \"$local_override\" >/dev/null"
	if command -v apparmor_parser >/dev/null 2>&1 && [[ -f "$profile" ]]; then
		run "${SUDO[@]}" apparmor_parser -r "$profile" || warn "apparmor_parser reload failed"
	else
		# Fallback: try service reload
		if systemctl list-units --type=service | grep -q apparmor; then
			run "${SUDO[@]}" systemctl reload apparmor || true
		fi
	fi
}
