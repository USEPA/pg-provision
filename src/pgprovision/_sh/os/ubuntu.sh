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

_is_valid_pgdata() {
	local d="${1:?}"
	[[ -d "$d" && -f "$d/PG_VERSION" && -f "$d/global/pg_control" ]]
}

_current_cluster_datadir() {
	local d=""
	if command -v pg_lsclusters >/dev/null 2>&1; then
		d=$(pg_lsclusters --no-header 2>/dev/null | awk '$1=="'"${PG_VERSION}"'" && $2=="main"{print $6; exit}')
	fi
	if [[ -z "$d" && -r "/etc/postgresql/${PG_VERSION}/main/postgresql.conf" ]]; then
		d=$(awk -F= '/^[[:space:]]*data_directory[[:space:]]*=/ { v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); gsub(/^'\''|'\''$/, "", v); gsub(/^"|"$/, "", v); print v; exit }' \
			"/etc/postgresql/${PG_VERSION}/main/postgresql.conf" 2>/dev/null || true)
	fi
	printf '%s\n' "$d"
}

# Ubuntu self-heal preflight: detect and repair broken default cluster safely.
# Non-destructive: never delete a directory that looks like valid PGDATA.
_ubuntu_self_heal_cluster() {
	local conf="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
	local datadir reason=() broken="false"
	datadir="$(_current_cluster_datadir)"

	# Detect haunted metadata
	if ! pg_lsclusters >/dev/null 2>&1; then
		broken="true"
		reason+=("pg_lsclusters error")
	fi
	# No cluster rows and no metadata dir → treat as broken (packaging failed to create main)
	local has_row=""
	if command -v pg_lsclusters >/dev/null 2>&1; then
		has_row=$(pg_lsclusters --no-header 2>/dev/null | awk '$1=="'"${PG_VERSION}"'" && $2=="main"{print "yes"; exit}')
	fi
	if [[ -z "$has_row" && ! -e "/etc/postgresql/${PG_VERSION}/main" ]]; then
		broken="true"
		reason+=("no ${PG_VERSION}/main cluster")
	fi
	if [[ -r "$conf" ]]; then
		local owner group
		owner=$(stat -c '%U' -- "$conf" 2>/dev/null || echo "")
		group=$(stat -c '%G' -- "$conf" 2>/dev/null || echo "")
		[[ "$owner:$group" != "postgres:postgres" ]] && {
			broken="true"
			reason+=("conf owner root")
		}
		[[ -n "$datadir" && ! -d "$datadir" ]] && {
			broken="true"
			reason+=("missing data_directory")
		}
	fi
	if [[ -n "$datadir" && -d "$datadir" ]]; then
		if ! _is_valid_pgdata "$datadir"; then
			broken="true"
			reason+=("invalid PGDATA layout")
		fi
	fi
	[[ "$broken" != "true" ]] && return 0
	warn "Ubuntu self-heal: detected broken cluster (${reason[*]})"

	# Stop service safely
	os_stop "postgresql@${PG_VERSION}-main" || true

	local target real="${datadir:-}"
	if [[ -n "$real" ]] && _is_valid_pgdata "$real"; then
		# ADOPT existing valid PGDATA (non-destructive): rebuild metadata only
		target="$real"
		# Remove stale metadata if present
		if [[ -d "/etc/postgresql/${PG_VERSION}/main" ]]; then
			run "${SUDO[@]}" rm -rf "/etc/postgresql/${PG_VERSION}/main"
		fi
		local tmp="/var/lib/postgresql/${PG_VERSION}/tmp-adopt.$$"
		run "${SUDO[@]}" install -d -m 0700 -- "$tmp"
		run "${SUDO[@]}" pg_createcluster "${PG_VERSION}" main -d "$tmp"
		ubuntu_apparmor_allow_datadir "$target" || true
		local target_lit
		target_lit=$(printf '%s' "$target" | sed "s/'/''/g")
		# Use shared helper to replace or append the setting consistently
		write_key_value_dropin "$conf" data_directory "'${target_lit}'"
		run "${SUDO[@]}" rm -rf -- "$tmp"
	else
		# No valid data: safe to drop stale metadata and recreate fresh
		run "${SUDO[@]}" pg_dropcluster --stop "${PG_VERSION}" main || true
		# Ensure metadata is gone
		if [[ -d "/etc/postgresql/${PG_VERSION}/main" ]]; then
			run "${SUDO[@]}" rm -rf "/etc/postgresql/${PG_VERSION}/main"
		fi
		target="/var/lib/postgresql/${PG_VERSION}/main"
		if [[ "${DATA_DIR:-auto}" != "auto" && -n "${DATA_DIR}" ]]; then
			target="${DATA_DIR}"
		fi
		run "${SUDO[@]}" install -d -m 0700 -- "$target"
		ubuntu_apparmor_allow_datadir "$target" || true
		run "${SUDO[@]}" pg_createcluster "${PG_VERSION}" main -d "$target"
	fi

	# Ensure config ownership and start
	if [[ -d "/etc/postgresql/${PG_VERSION}/main" ]]; then
		run "${SUDO[@]}" chown -R postgres:postgres "/etc/postgresql/${PG_VERSION}/main"
	fi
	os_enable_and_start "postgresql@${PG_VERSION}-main"
	log "Ubuntu self-heal: ensured ${PG_VERSION}/main is healthy (data=${target})"
}

os_init_cluster() {
	local data_dir="${1:-auto}"
	# Ubuntu auto-creates the default cluster when postgresql-${PG_VERSION} is installed via PGDG.
	# A custom data dir requires cluster tooling.

	# Run Ubuntu self-heal preflight (guarded; full logic planned)
	if [[ "${SELF_HEAL:-true}" == "true" ]]; then
		_ubuntu_self_heal_cluster || true
	fi

	if [[ "$data_dir" != "auto" && -n "$data_dir" ]]; then
		# Ensure the postgresql-common tools exist if we plan to move/create clusters.
		if ! "${SUDO[@]}" bash -lc 'command -v pg_dropcluster >/dev/null 2>&1 && command -v pg_createcluster >/dev/null 2>&1'; then
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
			os_enable_and_start "postgresql@${PG_VERSION}-main"
			return 0
		fi

		# We need to (re)create the cluster pointing at the requested data_dir.
		# Stop service (best-effort; works even if inactive).
		soft_run "stop service for relocation" os_stop "postgresql@${PG_VERSION}-main"
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
	os_enable_and_start "postgresql@${PG_VERSION}-main"
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
	if command -v systemctl >/dev/null 2>&1; then
		run "${SUDO[@]}" systemctl enable --now "$svc"
	else
		# Fallback for environments without systemd (e.g., WSL/containers)
		run "${SUDO[@]}" pg_ctlcluster "${PG_VERSION}" main start
	fi
}

os_restart() {
	local svc="${1:-postgresql@${PG_VERSION}-main}"
	if command -v systemctl >/dev/null 2>&1; then
		run "${SUDO[@]}" systemctl restart "$svc"
	else
		run "${SUDO[@]}" pg_ctlcluster "${PG_VERSION}" main restart
	fi
}

os_stop() {
	local svc="${1:-postgresql@${PG_VERSION}-main}"
	if command -v systemctl >/dev/null 2>&1; then
		run "${SUDO[@]}" systemctl stop "$svc"
	else
		run "${SUDO[@]}" pg_ctlcluster "${PG_VERSION}" main stop
	fi
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
