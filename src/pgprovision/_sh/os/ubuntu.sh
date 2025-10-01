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

#pgdata is valid if:
#1.) Directory exists.
#2.) Version marker exists.
#3.) Control file exists.

_is_valid_pgdata() {
	local d="${1:?}"
	[[ -d "$d" ]] || return 1
	[[ -f "$d/PG_VERSION" ]] || return 1
	[[ -d "$d/global" && -f "$d/global/pg_control" ]] || return 1
	[[ -d "$d/base" ]] || return 1
	# Accept either wal dir (>=10) or xlog (<10); allow symlinked WAL
	[[ -d "$d/pg_wal" || -L "$d/pg_wal" || -d "$d/pg_xlog" || -L "$d/pg_xlog" ]] || return 1
	return 0
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

# Ubuntu self-heal preflight: detect and repair broken default cluster safely
# Non-destructive: never delete a directory that looks like valid PGDATA.
_ubuntu_self_heal_cluster() {
	log "Ubuntu self-heal preflight: scanning ${PG_VERSION}/main"

	local conf="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
	local etcdir="/etc/postgresql/${PG_VERSION}/main"
	local verdir="/etc/postgresql/${PG_VERSION}"
	local quarantine_root="/var/lib/postgresql/.pgprovision-quarantine"
	local datadir reason=() broken="false"

	# Ensure quarantine root exists (outside /etc/postgresql)
	run "${SUDO[@]}" install -d -m 0700 -- "$quarantine_root"

	# --- Sweep leftovers from previous runs: move any *.broken.* OUT of verdir ---
	if [[ -d "$verdir" ]]; then
		local d base dest ts
		shopt -s nullglob
		for d in "$verdir"/*.broken.*; do
			[[ -d "$d" ]] || continue
			base=$(basename -- "$d")
			ts=$(date +%s)
			dest="${quarantine_root}/${PG_VERSION}-${base}-${ts}"
			must_run "quarantine leftover $base -> $dest" "${SUDO[@]}" mv -- "$d" "$dest"
		done
		shopt -u nullglob
	fi
	# ---------------------------------------------------------------------------

	datadir="$(_current_cluster_datadir)"

	# 0) pg_lsclusters must run cleanly (ok to mark broken if missing)
	if command -v pg_lsclusters >/dev/null 2>&1; then
		if ! pg_lsclusters >/dev/null 2>&1; then
			broken="true"
			reason+=("pg_lsclusters error")
		fi
	fi

	# 1) Does a ${PG_VERSION}/main row exist?
	local has_row=""
	if command -v pg_lsclusters >/dev/null 2>&1; then
		# Prefer the column output; it's stable across releases.
		has_row=$(pg_lsclusters --no-header 2>/dev/null |
			awk -v v="$PG_VERSION" '$1==v && $2=="main"{print "yes"; exit}')
		[[ -z "$has_row" ]] && {
			broken="true"
			reason+=("no cluster row ${PG_VERSION}/main")
		}
	fi

	# 2) Config directory must exist
	[[ ! -d "$etcdir" ]] && {
		broken="true"
		reason+=("missing $etcdir")
	}

	# 3) Validate/repair config readability (only if files exist)
	_conf_readable_by_postgres() { # unchanged logic from your version
		local f="${1:?}"
		[[ -e "$f" ]] || {
			echo "missing $(basename "$f")"
			return 1
		}
		if command -v runuser >/dev/null 2>&1; then
			runuser -u postgres -- test -r "$f" && return 0
		elif command -v sudo >/dev/null 2>&1; then
			sudo -n -u postgres test -r "$f" 2>/dev/null && return 0
		elif id postgres >/dev/null 2>&1; then
			su -s /bin/sh -c "test -r \"$f\"" postgres 2>/dev/null && return 0
		fi
		local owner group mode om
		owner=$(stat -c '%U' -- "$f" 2>/dev/null || echo "")
		group=$(stat -c '%G' -- "$f" 2>/dev/null || echo "")
		mode=$(stat -c '%a' -- "$f" 2>/dev/null || echo "")
		[[ -z "$mode" ]] && {
			echo "$(basename "$f") unreadable (stat failed)"
			return 1
		}
		om=$((8#$mode))
		if { [[ "$owner" == "postgres" ]] && ((om & 0400)); } ||
			{ [[ "$group" == "postgres" ]] && ((om & 0040)); } ||
			((om & 0004)); then
			((om & 0022)) && warn "$(basename "$f") group/other-writable (mode $mode)"
			return 0
		fi
		echo "$(basename "$f") not readable by postgres (owner=$owner group=$group mode=$mode)"
		return 1
	}

	if [[ -d "$etcdir" ]]; then
		local f msg rc
		for f in "$conf" "$etcdir/pg_hba.conf" "$etcdir/pg_ident.conf"; do
			if [[ ! -e "$f" ]]; then
				broken="true"
				reason+=("missing $(basename "$f")")
				continue
			fi
			msg=$(_conf_readable_by_postgres "$f")
			rc=$?
			if ((rc != 0)); then
				# safe Debian-ish repair; re-check once
				soft_run "fix ownership $(basename "$f")" "${SUDO[@]}" chown root:postgres -- "$f"
				soft_run "fix mode $(basename "$f")" "${SUDO[@]}" chmod 0640 -- "$f"
				if ! msg=$(_conf_readable_by_postgres "$f"); then
					broken="true"
					reason+=("$msg")
				fi
			fi
		done
	fi

	# 4) Resolve datadir if unknown
	if [[ -z "$datadir" && -r "$conf" ]]; then
		datadir=$(awk -F= '/^[[:space:]]*data_directory[[:space:]]*=/{gsub(/[#"].*$/,"",$2); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2; exit}' "$conf")
		[[ -z "$datadir" ]] && datadir="/var/lib/postgresql/${PG_VERSION}/main"
	fi

	# 5) PGDATA sanity (owner/mode/layout/version)
	if [[ -n "$datadir" && -d "$datadir" ]]; then
		local d_owner d_group d_mode
		d_owner=$(stat -c '%U' -- "$datadir" 2>/dev/null || echo "")
		d_group=$(stat -c '%G' -- "$datadir" 2>/dev/null || echo "")
		d_mode=$(stat -c '%a' -- "$datadir" 2>/dev/null || echo "")
		[[ "$d_owner:$d_group" != "postgres:postgres" ]] && {
			broken="true"
			reason+=("PGDATA owner not postgres ($d_owner:$d_group)")
		}
		case "$d_mode" in 700 | 750) : ;; *)
			broken="true"
			reason+=("PGDATA mode $d_mode (expect 700/750)")
			;;
		esac
		if ! _is_valid_pgdata "$datadir"; then
			broken="true"
			reason+=("invalid PGDATA layout")
		elif [[ -f "$datadir/PG_VERSION" ]]; then
			local on_disk_ver
			on_disk_ver=$(tr -d '\n' <"$datadir/PG_VERSION" 2>/dev/null)
			[[ -n "$on_disk_ver" && "$on_disk_ver" != "$PG_VERSION" ]] && {
				broken="true"
				reason+=("PG_VERSION mismatch: $on_disk_ver != $PG_VERSION")
			}
		fi
	elif [[ -n "$datadir" && ! -d "$datadir" ]]; then
		broken="true"
		reason+=("missing data_directory: $datadir")
	fi

	# 6) systemd generator / start.conf sanity
	local startconf="$etcdir/start.conf"
	if [[ -e "$startconf" ]]; then
		# First non-comment, non-blank token
		local startmode
		startmode=$(awk 'BEGIN{FS="[ \t]+"} /^[[:space:]]*(#|$)/{next} {print $1; exit}' \
			"$startconf" 2>/dev/null)
		case "$startmode" in
		auto | manual | disabled) : ;;
		*)
			broken="true"
			reason+=("bad start.conf${startmode:+: $startmode}")
			;;
		esac
	fi

	# 7) server binary presence
	[[ ! -x "/usr/lib/postgresql/${PG_VERSION}/bin/postgres" ]] && {
		broken="true"
		reason+=("server binary missing")
	}

	# --- Early exit if all good ---
	[[ "$broken" != "true" ]] && return 0

	# 8) Quarantine *out of /etc/postgresql* if: no row, etcdir exists, and datadir is missing/invalid
	local datadir_bad="false"
	if [[ -z "$datadir" || ! -d "$datadir" ]]; then
		datadir_bad="true"
	elif ! _is_valid_pgdata "$datadir"; then
		datadir_bad="true"
	fi

	if [[ -z "$has_row" && -d "$etcdir" && "$datadir_bad" == "true" ]]; then
		local stamp dest
		stamp=$(date +%s)
		dest="${quarantine_root}/${PG_VERSION}-main-${stamp}"
		must_run "quarantine $etcdir -> $dest" "${SUDO[@]}" mv -T -- "$etcdir" "$dest"
		log "Ubuntu self-heal: quarantined stale /etc/postgresql/${PG_VERSION}/main -> $dest"
		# Make sure verdir exists (postinst may create it anyway)
		run "${SUDO[@]}" install -d -m 0755 -- "$verdir"
	fi

	warn "Ubuntu self-heal: detected broken cluster (${reason[*]})"
}

os_init_cluster() {
	local data_dir="${1:-auto}"
	# Ubuntu auto-creates the default cluster when postgresql-${PG_VERSION} is installed via PGDG.
	# A custom data dir requires cluster tooling.

	local has_row=""
	if command -v pg_lsclusters >/dev/null 2>&1; then
		has_row=$(pg_lsclusters --no-header 2>/dev/null |
			awk '$1=="'"${PG_VERSION}"'" && $2=="main"{print "yes"; exit}')
	fi

	if [[ "$data_dir" == "auto" ]]; then
		if [[ -z "$has_row" ]]; then

			local def="/var/lib/postgresql/${PG_VERSION}/main"
			run "${SUDO[@]}" install -d -m 0700 -- "$def"
			ubuntu_apparmor_allow_datadir "$def" || true
			run "${SUDO[@]}" pg_createcluster "${PG_VERSION}" main -d "$def"
		fi
		os_enable_and_start "postgresql@${PG_VERSION}-main"
		return 0
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
