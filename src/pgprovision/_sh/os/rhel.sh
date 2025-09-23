#!/usr/bin/env bash
#NOTE: this file is sourced by provision.sh

# Expect these from the caller: run(), err(), and variables PG_VERSION, REPO_KIND
: "${PG_VERSION:=16}"
: "${REPO_KIND:=pgdg}"

_pkgmgr() {
	if command -v dnf >/dev/null 2>&1; then echo dnf; elif command -v yum >/dev/null 2>&1; then echo yum; else return 1; fi
}

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
	run "${SUDO[@]}" install -d -m 0755 -- "$(dirname "$dropin")"
	# Use tee under sudo to avoid redirection permission issues
	run bash -c "printf '%s\n' '[Unit]' 'RequiresMountsFor=${pgdata}' '' '[Service]' 'Environment=PGDATA=${pgdata}' \
                | ${SUDO[*]} tee '${dropin}' >/dev/null"
	run "${SUDO[@]}" systemctl daemon-reload
}

_rhel_selinux_label_datadir() {
	local dir="${1:?dir}"
	if ! command -v semanage >/dev/null 2>&1; then
		warn "semanage not available; skipping SELinux fcontext for ${dir} (install policycoreutils-python-utils)."
		return 0
	fi
	if ! run "${SUDO[@]}" semanage fcontext -a -t postgresql_db_t "${dir}(/.*)?"; then
		run "${SUDO[@]}" semanage fcontext -m -t postgresql_db_t "${dir}(/.*)?" || {
			warn "Failed to set SELinux context for PGDATA: ${dir}"
			return 0
		}
	fi
	run "${SUDO[@]}" restorecon -Rv "${dir}"
}

os_prepare_repos() {
	local repo_kind="${1:-${REPO_KIND}}"
	local pm
	pm="$(_pkgmgr)" || {
		err "No dnf/yum found"
		exit 2
	}
	local PM=("${SUDO[@]}" "$pm")
	if [[ "$repo_kind" == "pgdg" ]]; then
		# Use PGDG and disable AppStream module
		run "${PM[@]}" -y module reset postgresql || true
		run "${PM[@]}" -y module disable postgresql || true
		local rel arch rpm_url
		rel="$(rpm -E %rhel)"
		arch="$(uname -m)"
		case "$arch" in x86_64 | aarch64 | ppc64le | s390x) : ;; *) arch="x86_64" ;; esac
		rpm_url="https://download.postgresql.org/pub/repos/yum/reporpms/EL-${rel}-${arch}/pgdg-redhat-repo-latest.noarch.rpm"
		must_run "install PGDG repo" "${PM[@]}" -y install "$rpm_url"
	else
		# Use OS AppStream module at the requested major version
		run "${PM[@]}" -y module reset postgresql || true
		must_run "enable AppStream module postgresql:${PG_VERSION}" "${PM[@]}" -y module enable "postgresql:${PG_VERSION}"
	fi
}

os_install_packages() {
	local repo_kind="${1:-${REPO_KIND}}"
	local pm
	pm="$(_pkgmgr)" || {
		err "No dnf/yum found"
		exit 2
	}
	local PM=("${SUDO[@]}" "$pm")
	if [[ "$repo_kind" == "pgdg" ]]; then
		must_run "install PGDG packages" "${PM[@]}" -y install \
			"postgresql${PG_VERSION}" "postgresql${PG_VERSION}-server" "postgresql${PG_VERSION}-contrib"
	else
		must_run "install AppStream packages" "${PM[@]}" -y install postgresql postgresql-server postgresql-contrib
	fi
}

os_init_cluster() {
	local data_dir="${1:-auto}"
	local svc="$(_rhel_service_name)"
	# Choose setup command depending on packaging
	local -a setup_cmd=()
	if command -v postgresql-setup >/dev/null 2>&1 && [[ "$svc" == "postgresql" ]]; then
		setup_cmd=("${SUDO[@]}" postgresql-setup --initdb)
	elif [[ -x "/usr/pgsql-${PG_VERSION}/bin/postgresql-${PG_VERSION}-setup" ]]; then
		setup_cmd=("${SUDO[@]}" "/usr/pgsql-${PG_VERSION}/bin/postgresql-${PG_VERSION}-setup" initdb)
	fi

	if [[ "$data_dir" == "auto" ]]; then
		if ((${#setup_cmd[@]})); then
			run "${setup_cmd[@]}"
		else
			# Fallback to initdb if setup helper unavailable
			local pgdata="$(_rhel_default_pgdata_for_service)"
			must_run "create PGDATA" "${SUDO[@]}" install -d -m 0700 -- "$pgdata"
			must_run "chown PGDATA to postgres" "${SUDO[@]}" chown -R postgres:postgres -- "$pgdata"
			must_run "initdb default PGDATA" "${SUDO[@]}" -u postgres initdb -D "$pgdata"
		fi
		must_run "enable+start $svc" "${SUDO[@]}" systemctl enable --now "$svc"
	else
		must_run "create custom PGDATA" "${SUDO[@]}" install -d -m 0700 -- "$data_dir"
		must_run "chown custom PGDATA" "${SUDO[@]}" chown -R postgres:postgres -- "$data_dir"
		must_run "chmod 0700 custom PGDATA" "${SUDO[@]}" chmod 0700 -- "$data_dir"
		_rhel_selinux_label_datadir "$data_dir" || warn "SELinux label for $data_dir did not apply"
		if command -v initdb >/dev/null 2>&1; then
			if [[ ! -d "$data_dir/base" ]]; then
				must_run "initdb custom PGDATA" "${SUDO[@]}" -u postgres initdb -D "$data_dir"
			fi
		else
			err "initdb not found; cannot initialize custom data dir at ${data_dir}"
			exit 2
		fi
		_rhel_set_pgdata_override "$svc" "$data_dir"
		must_run "enable+start $svc" "${SUDO[@]}" systemctl enable --now "$svc"
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
	run "${SUDO[@]}" systemctl enable --now "$svc"
}
os_restart() {
	local svc="$(_rhel_service_name)"
	run "${SUDO[@]}" systemctl restart "$svc"
}
