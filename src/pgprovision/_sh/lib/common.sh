# lib/common.sh
# shellcheck shell=bash
[[ ${__COMMON_LIB_LOADED:-0} -eq 1 ]] && return 0
__COMMON_LIB_LOADED=1

_c_green=$'\033[0;32m'
_c_yellow=$'\033[0;33m'
_c_red=$'\033[0;31m'
_c_reset=$'\033[0m'

log() { echo -e "${_c_green}[pgprovision]${_c_reset} $*"; }
warn() { echo -e "${_c_yellow}[pgprovision][warn]${_c_reset} $*" 1>&2; }
err() { echo -e "${_c_red}[pgprovision][error]${_c_reset} $*" 1>&2; }
run() {
	echo "+ $*"
	"$@"
}

#Error handling ------------------------------------------------
must_run() {
	local msg="$1"
	shift
	if ! run "$@"; then
		err "$msg (rc=$?)"
		exit 1
	fi
}

soft_run() {
	local msg="$1"
	shift
	run "$@" || {
		warn "$msg (rc=$?)"
		return 0
	}
}
#----------------------------------------------------------------

write_key_value_dropin() {
	local f="$1" key="$2" val="$3"
	: >/dev/null
	touch "$f"
	if grep -E -q "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
		run sed -i -E "s|^[[:space:]]*(${key})[[:space:]]*=.*$|\1 = ${val}|" "$f"
	else
		run bash -c "printf '%s\n' \"${key} = ${val}\" >> \"$f\""
	fi
}

ensure_line() {
	local f="$1"
	shift
	local line="$*"
	grep -Fqx -- "$line" "$f" 2>/dev/null || run bash -c "printf '%s\n' \"$line\" >> \"$f\""
}

ensure_dir() {
	local d="$1"
	if [[ -d "$d" ]]; then
		echo "+ dir exists: $d"
		return 0
	fi
	if install -d -m 0755 "$d" 2>/dev/null; then
		echo "+ install -d -m 0755 $d"
		return 0
	fi
	if [[ $(id -u) -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
		must_run "create directory $d" sudo -n install -d -m 0755 "$d"
	else
		err "Cannot create directory $d (no permission or sudo)"
		exit 1
	fi
}
