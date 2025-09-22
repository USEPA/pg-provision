load_profile_overrides() {
	PROFILE_OVERRIDES=()
	[[ -z "${PROFILE:-}" ]] && return 0
	local p="${SCRIPT_DIR}/profiles/${PROFILE}.conf"
	if [[ ! -r "$p" ]]; then
		warn "Profile not found: $PROFILE ($p)"
		return 0
	fi
	while IFS= read -r line; do
		[[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
		local key="${line%%=*}"
		local val="${line#*=}"
		# trim spaces around key and leading spaces in value
		key="${key//[[:space:]]/}"
		val="${val#"${val%%[![:space:]]*}"}"
		PROFILE_OVERRIDES+=("${key}=${val}")
	done <"$p"
}
